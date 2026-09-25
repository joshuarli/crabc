#!/usr/bin/env python3
"""Bind one current-source ABI-differential evidence set for its gate.

The `compat.abi-differential` gate family names six retained leaf reports:
the native ABI inventory, complete ELF facts, the public-dynamic ratchet, the
compiler declaration inventory, the native selection report, and the ordinary
public-data link receipt. Every one of them is replayed only against explicit
products (and, for selection, explicit companion receipts), so a gate reader
cannot validate one of them from its path alone.

`assemble` takes the products and the four natively collected reports,
produces the ratchet check and selection report from them into the set
directory, and writes `abi-evidence.json`; `validate` replays every leaf
reader against it. Assembly and gate evaluation both run in the pinned
image: the ratchet and selection reports record their inputs by checkout
path, so a set built on the host would not replay at `/workspace`. The receipt holds
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
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
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
# Reports collected by their own native commands; assembly produces the rest.
COLLECTED_REPORTS = (
    "native_abi_inventory",
    "native_abi_elf_facts",
    "header_declaration_inventory",
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
# The one companion that is checked-in generated source rather than `.work`
# evidence; the source seal already binds its bytes.
SOURCE_COMPANIONS = {
    "headers_layouts_aggregate_report": "compat/x86_64/generated/headers_layouts_aggregate/report.json",
}
COMPANIONS_SCHEMA = "crabc.x86_64-abi-differential-companions/v1"
COMPANIONS_NAME = "companions.json"
# Companions whose receipts only a family admission flow produces. Collection
# names them; their families keep the selection blockers until admitted.
FAMILY_FLOW_COMPANIONS = {
    "text_family_semantic_report": "./scripts/dev-x86_64.sh owned-text-math-locale-stdio-family assemble",
    "posix_sysv_signal_admission_report": "./scripts/dev-x86_64.sh owned-posix-native",
}


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


def _companion_path(name: str, value: object) -> Path:
    """Resolve one companion: a `.work` receipt or its fixed source report."""
    if name in SOURCE_COMPANIONS:
        require(value == SOURCE_COMPANIONS[name], f"{name} must be its source report {SOURCE_COMPANIONS[name]}")
        path = ROOT / SOURCE_COMPANIONS[name]
        require(path.is_file() and not path.is_symlink(), f"{name} source report is absent")
        return path
    return _checkout_path(value, "file", name)


def _companion_relative(name: str, path: Path) -> str:
    if name in SOURCE_COMPANIONS:
        _companion_path(name, SOURCE_COMPANIONS[name])
        require(Path(os.path.abspath(path)) == ROOT / SOURCE_COMPANIONS[name],
                f"{name} must be its source report {SOURCE_COMPANIONS[name]}")
        return SOURCE_COMPANIONS[name]
    return _relative(path, name)


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
            path = _companion_path(name, entry.get("path"))
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
    import native_abi_selection

    try:
        report = _selection(evidence, closure=True)
    except native_abi_selection.SelectionError as error:
        # The replay already reconstructed the report; name what stays open.
        blockers = inventory.read_json(evidence.reports["native_abi_selection"], "selection report")["closure"]["blockers"]
        codes: dict[str, int] = {}
        for blocker in blockers:
            codes[str(blocker.get("code"))] = codes.get(str(blocker.get("code")), 0) + 1
        families = sorted({
            str(blocker["family"]) for blocker in blockers
            if blocker.get("code") == "family-semantic-evidence-unavailable" and "family" in blocker
        })
        raise EvidenceError(
            f"{error}: {len(blockers)} blockers ("
            + ", ".join(f"{code}={count}" for code, count in sorted(codes.items()))
            + f"); family semantic evidence unavailable for {len(families)} families"
        ) from error
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


# ---------------------------------------------------------------------------
# Companion collection. Each selection companion keyword names the existing
# runner that produces its receipt; `collect-companions` runs them all against
# one cohort (the assemble inputs) so one assemble binds every companion.


@dataclass(frozen=True)
class Cohort:
    """The seven assemble inputs every companion producer is run against."""

    static_product: Path
    dynamic_product: Path
    static_preparation: Path
    native_abi_inventory: Path
    native_abi_elf_facts: Path
    header_declaration_inventory: Path
    public_data_ordinary_link: Path

    @classmethod
    def from_arguments(cls, arguments: argparse.Namespace) -> "Cohort":
        return cls(**{name: Path(os.path.abspath(getattr(arguments, name))) for name in (*INPUT_KINDS, *COLLECTED_REPORTS)})

    def record(self) -> dict[str, str]:
        return {name: _relative(getattr(self, name), name) for name in (*INPUT_KINDS, *COLLECTED_REPORTS)}


@dataclass(frozen=True)
class CompanionProducer:
    """One companion's existing runner.

    `command(cohort, reports, output)` returns the argv (run at the checkout
    root) and any extra environment; `output` is the producer's fresh output
    directory. `report(output)` locates the receipt it wrote. `requires` names
    companions whose receipts the runner consumes.
    """

    keyword: str
    command: Callable[[Cohort, Mapping[str, Path], Path], tuple[list[str], dict[str, str]]]
    report: Callable[[Path], Path]
    requires: tuple[str, ...] = ()
    output_parent: str | None = None


def _in(output: Path) -> Path:
    return output / "report.json"


def _only_child_report(output: Path) -> Path:
    """Runners that `mktemp -d "$TMPDIR/..."` write exactly one evidence tree."""
    children = [path for path in output.iterdir() if path.is_dir() and not path.is_symlink()]
    require(len(children) == 1, f"{output} does not hold exactly one runner evidence tree")
    return children[0] / "report.json"


def _tmpdir_env(output: Path) -> dict[str, str]:
    output.mkdir()
    return {"TMPDIR": str(output)}


def _p(cohort: Cohort) -> list[str]:
    return ["--static-preparation", str(cohort.static_preparation), "--static-product", str(cohort.static_product),
            "--dynamic-product", str(cohort.dynamic_product)]


PRODUCERS = (
    CompanionProducer(
        "loader_debug_report",
        lambda c, r, o: (["bash", "compat/x86_64/run_loader_debug_abi.sh", "collect", "--output", str(o),
                          "--static-product", str(c.static_product), "--dynamic-product", str(c.dynamic_product)], {}),
        _in),
    CompanionProducer(
        "ordinary_declaration_abi_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/native_declaration_abi.py", "--collect",
                          "--header-report", str(c.header_declaration_inventory), "--output", str(o)], {}),
        _in, output_parent=".work/x86_64/native-declaration-abi"),
    CompanionProducer(
        "compiler_helper_aggregate_report",
        lambda c, r, o: (["bash", "builtins/run_x86_64_compiler_helper_aggregate.sh"],
                         {"CRABC_COMPILER_HELPER_WORK_DIR": str(o)}),
        _in),
    CompanionProducer(
        "loader_runtime_registry_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/loader_runtime_registry_evidence.py", "collect",
                          "--base-inventory", str(c.native_abi_inventory), "--elf-report", str(c.native_abi_elf_facts),
                          *_p(c), "--output", str(o)], {}),
        _in),
    CompanionProducer(
        "pthread_alias_contract_report",
        lambda c, r, o: (["bash", "compat/x86_64/run_owned_pthread_alias_contract.sh", "--receipt-dir", str(o),
                          "--product-report", str(r["loader_debug_report"]),
                          str(c.static_product), str(c.dynamic_product)], {}),
        _in, requires=("loader_debug_report",)),
    CompanionProducer(
        "prepared_worker_tls_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/prepared_worker_tls_evidence.py", "collect",
                          "--base-inventory", str(c.native_abi_inventory), "--elf-report", str(c.native_abi_elf_facts),
                          *_p(c), "--output", str(o)], {}),
        _in),
    CompanionProducer(
        "errno_storage_lifecycle_report",
        lambda c, r, o: (["bash", "compat/x86_64/run_owned_errno_storage_lifecycle.sh",
                          "--static-sysroot", str(c.static_product), str(c.dynamic_product)], _tmpdir_env(o)),
        _only_child_report),
    CompanionProducer(
        "native_c_allocator_boundary_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/native_c_allocator_boundary.py", "collect", *_p(c),
                          "--elf-facts-report", str(c.native_abi_elf_facts), "--output", str(o)], {}),
        _in),
    CompanionProducer(
        "stdio_alias_contract_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/owned_stdio_alias_contract_reader.py", "collect",
                          "--output", str(o), *_p(c), "--historical-facts", str(c.native_abi_elf_facts)], {}),
        _in),
    CompanionProducer(
        "crt_startup_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/installed_crt_startup_evidence.py", "collect",
                          "--output", str(o), *_p(c), "--historical-facts", str(c.native_abi_elf_facts)], {}),
        _in),
    CompanionProducer(
        "syscall_alias_contract_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/owned_syscall_alias_contract_reader.py", "collect",
                          "--output", str(o), *_p(c), "--elf-facts", str(c.native_abi_elf_facts),
                          "--base-inventory", str(c.native_abi_inventory),
                          "--image-id", os.environ.get("CRABC_X86_SYSCALL_ALIAS_IMAGE_ID", "")], {}),
        _in),
    CompanionProducer(
        "utmpx_receipt_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/owned_utmpx_receipt.py", "collect", *_p(c),
                          "--output", str(o)], {}),
        _in),
    CompanionProducer(
        "pthread_timed_feature_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/owned_pthread_timed_feature_contract_reader.py",
                          "--collect-native", "--root", str(ROOT), "--receipt-dir", str(o),
                          "--product-report", str(r["loader_debug_report"]), *_p(c)], {}),
        _in, requires=("loader_debug_report",)),
    CompanionProducer(
        "resolver_alias_receipt_report",
        lambda c, r, o: (["bash", "compat/x86_64/run_owned_resolver_alias_contract.sh",
                          "--static-product", str(c.static_product), "--dynamic-product", str(c.dynamic_product),
                          "--static-preparation", str(c.static_preparation),
                          "--product-report", str(r["loader_debug_report"]),
                          "--elf-facts", str(c.native_abi_elf_facts), "--base-inventory", str(c.native_abi_inventory),
                          "--receipt-dir", str(o)], {}),
        _in, requires=("loader_debug_report",)),
    CompanionProducer(
        "locale_alias_contract_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/locale_alias_contract_receipt.py", "collect",
                          "--output", str(o)], {}),
        _in),
    CompanionProducer(
        "bsd_random_receipt_report",
        lambda c, r, o: (["bash", "compat/x86_64/run_owned_bsd_random.sh",
                          "--static-sysroot", str(c.static_product), str(c.dynamic_product)], _tmpdir_env(o)),
        _only_child_report),
    CompanionProducer(
        "public_data_declaration_runtime_report",
        lambda c, r, o: (["python3", "-B", "compat/x86_64/owned_public_data_variable_runtime.py", "collect", *_p(c),
                          "--header-report", str(c.header_declaration_inventory),
                          "--declaration-abi-report", str(r["ordinary_declaration_abi_report"]),
                          "--ordinary-link-report", str(c.public_data_ordinary_link),
                          "--errno-report", str(r["errno_storage_lifecycle_report"]), "--output", str(o)], {}),
        _in, requires=("ordinary_declaration_abi_report", "errno_storage_lifecycle_report")),
    CompanionProducer(
        "loader_structural_owner_receipt_report",
        lambda c, r, o: (["bash", "compat/x86_64/run_loader_structural_owner_contract.sh", "--output", str(o),
                          "--static-product", str(c.static_product), "--dynamic-product", str(c.dynamic_product),
                          "--static-preparation", str(c.static_preparation),
                          "--base-inventory", str(c.native_abi_inventory), "--full-facts", str(c.native_abi_elf_facts),
                          "--loader-debug-report", str(r["loader_debug_report"]),
                          "--loader-runtime-registry-report", str(r["loader_runtime_registry_report"])], {}),
        _in, requires=("loader_debug_report", "loader_runtime_registry_report")),
)


def collect_companions(cohort: Cohort, output: Path, *, only: Sequence[str] = ()) -> Path:
    """Run every companion producer once against one cohort.

    A failing producer is recorded with its log and exit status; companions
    that consume its receipt are recorded as blocked. Neither is ever bound
    into the manifest, so its selection blockers stay open. `only` restricts
    the run to named producers (and requires their prerequisites to succeed
    in the same run).
    """
    require(output.parent == OUTPUT_PARENT or output.parent.is_relative_to(OUTPUT_PARENT),
            f"output must be below {OUTPUT_PARENT.relative_to(ROOT)}")
    require(not output.exists(), "output must be fresh")
    require(set(only) <= {producer.keyword for producer in PRODUCERS}, f"unknown companion producer in {list(only)}")
    source = current_source()
    cohort.record()
    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    (output / "logs").mkdir()
    reports: dict[str, Path] = {name: ROOT / path for name, path in SOURCE_COMPANIONS.items()}
    outcomes: dict[str, dict[str, Any]] = {}
    for producer in PRODUCERS:
        if only and producer.keyword not in only:
            continue
        missing = [name for name in producer.requires if name not in reports]
        if missing:
            outcomes[producer.keyword] = {"status": "blocked", "requires": missing}
            continue
        # A producer with its own fixed output root takes this collection's
        # name as its immediate child there.
        if producer.output_parent:
            (ROOT / producer.output_parent).mkdir(parents=True, exist_ok=True)
            target = ROOT / producer.output_parent / output.name
        else:
            target = output / producer.keyword
        # Every runner gets its own scratch: a shared TMPDIR may contain the
        # supplied products, which several runners refuse to overlap.
        scratch = output / "tmp" / producer.keyword
        scratch.mkdir(parents=True)
        argv, environment = producer.command(cohort, reports, target)
        environment = {"TMPDIR": str(scratch), **environment}
        log = output / "logs" / f"{producer.keyword}.log"
        with log.open("wb") as stream:
            completed = subprocess.run(argv, cwd=ROOT, env={**os.environ, **environment},
                                       stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, check=False)
        outcome: dict[str, Any] = {"returncode": completed.returncode, "log": _relative(log, "log")}
        try:
            report = producer.report(target)
            produced = completed.returncode == 0 and report.is_file() and not report.is_symlink()
        except (OSError, EvidenceError):
            produced = False
        if produced:
            reports[producer.keyword] = report
            outcome.update({"status": "produced", "path": _relative(report, producer.keyword)})
        else:
            outcome["status"] = "failed"
        outcomes[producer.keyword] = outcome
        print(f"{producer.keyword}: {outcome['status']} ({completed.returncode})", flush=True)
    for name, command in FAMILY_FLOW_COMPANIONS.items():
        outcomes[name] = {"status": "family-flow", "command": command}
    require(current_source() == source, "source changed during companion collection")
    record = {
        "schema": COMPANIONS_SCHEMA,
        "source": source,
        "cohort": cohort.record(),
        "companions": {
            name: {"path": _companion_relative(name, path), "sha256": _sha256(path)}
            for name, path in sorted(reports.items())
        },
        "outcomes": outcomes,
    }
    manifest = output / COMPANIONS_NAME
    manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def load_companions(path: Path, cohort: Cohort) -> dict[str, Path]:
    """Admit one collection manifest for this cohort at the current source."""
    require(path.name == COMPANIONS_NAME, f"companion manifest must be named {COMPANIONS_NAME}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"companion manifest is unreadable: {error}") from error
    require(isinstance(record, dict) and set(record) == {"schema", "source", "cohort", "companions", "outcomes"}
            and record["schema"] == COMPANIONS_SCHEMA and isinstance(record["companions"], dict)
            and set(record["companions"]) <= set(SELECTION_COMPANIONS),
            "companion manifest does not match its schema")
    require(record["source"] == current_source(), "companion manifest was collected at another revision")
    require(record["cohort"] == cohort.record(), "companion manifest was collected against another cohort")
    companions: dict[str, Path] = {}
    for name, entry in record["companions"].items():
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256"}, f"companion {name} entry is malformed")
        companion = _companion_path(name, entry["path"])
        require(_sha256(companion) == entry["sha256"], f"companion {name} bytes changed after collection")
        companions[name] = companion
    return companions


def assemble(arguments: argparse.Namespace) -> Path:
    import native_abi_ratchet
    import native_abi_selection

    output = Path(os.path.abspath(arguments.output))
    require(output.parent == OUTPUT_PARENT or output.parent.is_relative_to(OUTPUT_PARENT),
            f"output must be below {OUTPUT_PARENT.relative_to(ROOT)}")
    require(not output.exists(), "output must be fresh")
    companions: dict[str, Path] = (
        load_companions(Path(os.path.abspath(arguments.companions)), Cohort.from_arguments(arguments))
        if arguments.companions is not None else {}
    )
    for value in arguments.selection_companion:
        name, separator, path = value.partition("=")
        require(separator == "=" and name in SELECTION_COMPANIONS and name not in companions,
                f"invalid or repeated selection companion: {value}")
        companions[name] = Path(os.path.abspath(path))
    source = current_source()
    inputs = {name: Path(os.path.abspath(getattr(arguments, name))) for name in INPUT_KINDS}
    reports = {name: Path(os.path.abspath(getattr(arguments, name))) for name in COLLECTED_REPORTS}
    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    reports["native_abi_ratchet"] = native_abi_ratchet.check(
        reports["native_abi_inventory"], output=output / "ratchet", **inputs,
    )
    selection_inputs = {
        "measurement_checkout": ROOT,
        "elf_report": reports["native_abi_elf_facts"],
        "base_inventory": reports["native_abi_inventory"],
        **inputs,
        "declaration_report": reports["header_declaration_inventory"],
        **companions,
    }
    if "loader_debug_report" in companions:
        selection_inputs["ordinary_link_report"] = reports["public_data_ordinary_link"]
    native_abi_selection.build_report(output=output / "selection", **selection_inputs)
    reports["native_abi_selection"] = output / "selection" / "report.json"
    record = {
        "schema": SCHEMA,
        "source": source,
        "inputs": {name: _relative(path, name) for name, path in inputs.items()},
        "reports": {
            name: {"path": _relative(reports[name], name), "sha256": _sha256(reports[name])} for name in REPORTS
        },
        "selection_companions": {
            name: {"path": _companion_relative(name, path), "sha256": _sha256(path)}
            for name, path in sorted(companions.items())
        },
    }
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
    for name in (*INPUT_KINDS, *COLLECTED_REPORTS):
        build.add_argument("--" + name.replace("_", "-"), dest=name, type=Path, required=True)
    build.add_argument("--selection-companion", action="append", default=[], metavar="KEYWORD=REPORT")
    build.add_argument("--companions", type=Path, metavar="COMPANIONS_JSON",
                       help="bind every companion from one collect-companions manifest for this cohort")
    build.add_argument("--output", type=Path, required=True)
    gather = commands.add_parser("collect-companions", help="run every selection companion producer on one cohort")
    for name in (*INPUT_KINDS, *COLLECTED_REPORTS):
        gather.add_argument("--" + name.replace("_", "-"), dest=name, type=Path, required=True)
    gather.add_argument("--only", action="append", default=[], metavar="KEYWORD")
    gather.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("validate", help="replay one assembled evidence set")
    check.add_argument("receipt", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "assemble":
            print(assemble(arguments))
        elif arguments.command == "collect-companions":
            manifest = collect_companions(Cohort.from_arguments(arguments), Path(os.path.abspath(arguments.output)),
                                          only=arguments.only)
            print(manifest)
            outcomes = json.loads(manifest.read_text(encoding="utf-8"))["outcomes"]
            return 0 if all(item["status"] in {"produced", "family-flow"} for item in outcomes.values()) else 1
        else:
            results = validate_receipt(ROOT, arguments.receipt)["results"]
            for name, result in results.items():
                print(f"{name}: {'met' if result['met'] else 'UNMET'}: {result['detail']}")
            return 0 if all(result["met"] for result in results.values()) else 1
        return 0
    except Exception as error:  # noqa: BLE001 - leaf reader errors are reported, not traced
        if not isinstance(error, (EvidenceError, OSError)) and type(error).__name__ not in (
            "RatchetError", "SelectionError", "InventoryError",
        ):
            raise
        print(f"ABI-differential evidence: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
