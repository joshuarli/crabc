#!/usr/bin/env python3
"""Evaluate an ordered x86 qualification gate as named, fail-closed conditions.

Each promotion-chain gate is the parity-ledger family with the same id. A gate
passes only when all of the following hold in the pinned native image:

* ``prerequisite-families``: every transitive ``depends_on`` family and every
  earlier chain gate records ``foundation-verified`` in ``parity.toml``;
* ``evidence[N]``: every ``native_evidence`` command of the gate family has a
  registered qualification reader here, and that reader validates retained or
  freshly executed evidence against the current source; and
* any gate-specific completion check (``capability.accounting``).

An evidence command without a registered reader, including a prose
placeholder, is an unmet condition. The owning lane closes it by making the
ledger command executable and registering one reader below; there is no
"future milestone" state. Readers never replace a leaf's own validator: they
select the retained evidence and call that validator.

Retained receipts written to caller-chosen directories are selected through a
publication pointer below ``.work/x86_64/qualification-evidence``. Publishing
validates the receipt first and records only its path and byte hash; the gate
reruns the receipt's own reader every time, so a stale or replaced receipt
cannot pass. Host evaluation (``native=False``) reports declarations only:
reader conditions stay unevaluated and the gate cannot pass there.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import generate_qualification_manifest as manifest


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
PUBLICATION_DIRECTORY = ROOT / ".work" / "x86_64" / "qualification-evidence"
CONDITIONS_SCHEMA = "crabc.x86_64-qualification-gate-conditions/v1"
PUBLICATION_SCHEMA = "crabc.x86_64-qualification-evidence-publication/v1"
COMPLETED_STATUS = "foundation-verified"
CHAIN = manifest.CHAIN


def pass_marker(gate: str) -> str:
    return f"x86 qualification gate {gate}: PASS"


class GateError(RuntimeError):
    """The gate contract itself is malformed; evaluation cannot proceed."""


class EvidenceUnmet(RuntimeError):
    """One evidence reader found a precise, reportable missing condition."""


def unmet_unless(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceUnmet(message)


def repository_relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_families(path: Path = LEDGER_PATH) -> dict[str, Mapping[str, Any]]:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"cannot read x86 parity ledger: {error}") from error
    rows = document.get("family")
    if not isinstance(rows, list):
        raise GateError("x86 parity ledger has no family table")
    families: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            raise GateError("x86 parity ledger family row is invalid")
        families[row["id"]] = row
    missing = [gate for gate in CHAIN if gate not in families]
    if missing:
        raise GateError("qualification chain gates have no ledger family: " + ", ".join(missing))
    return families


def prerequisite_families(gate: str, families: Mapping[str, Mapping[str, Any]]) -> list[tuple[str, str]]:
    """Return (family, reason) in dependency order, then earlier chain gates."""
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()

    def visit(identifier: str) -> None:
        dependencies = families[identifier].get("depends_on")
        if not isinstance(dependencies, list):
            raise GateError(f"family {identifier} dependencies are invalid")
        for dependency in dependencies:
            if not isinstance(dependency, str) or dependency not in families:
                raise GateError(f"family {identifier} depends on unknown family {dependency!r}")
            if dependency not in seen:
                seen.add(dependency)
                visit(dependency)
                ordered.append((dependency, "depends_on"))

    visit(gate)
    for predecessor in CHAIN[: CHAIN.index(gate)]:
        if predecessor not in seen:
            seen.add(predecessor)
            ordered.append((predecessor, "chain-order"))
    return ordered


# ---------------------------------------------------------------------------
# Evidence publications and readers


@dataclass(frozen=True)
class Publication:
    """One retained receipt kind that a gate selects through a pointer."""

    id: str
    gate: str
    receipt_name: str
    producer: str
    validate: Callable[[Path], Mapping[str, Any]]


@dataclass(frozen=True)
class EvidenceReader:
    """The qualification reader for one exact ledger evidence command.

    ``kind`` is ``publication`` (published retained receipt), ``report``
    (fixed-location report), ``ledger`` (checked-in source only) or
    ``execution`` (the gate case itself runs a self-contained native leaf).
    """

    gate: str
    command: str
    kind: str
    source: str
    read: Callable[["Evaluation"], str]


def _import_compat(name: str) -> Any:
    directory = str(ROOT / "compat" / "x86_64")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    return __import__(name)


def _validate_posix_native(path: Path) -> Mapping[str, Any]:
    return _import_compat("owned_posix_native_execution").validate_receipt(ROOT, path)


def _validate_loader_family(path: Path) -> Mapping[str, Any]:
    return _import_compat("owned_loader_family").validate_receipt(ROOT, path)


PUBLICATIONS: dict[str, Publication] = {
    publication.id: publication
    for publication in (
        Publication(
            "posix-native",
            "compat.posix-process",
            "native-execution.json",
            "./scripts/dev-x86_64.sh owned-posix-native ... --output NEW_DIR",
            _validate_posix_native,
        ),
        Publication(
            "loader-family",
            "compat.loader-corpus",
            "receipt.json",
            "./scripts/dev-x86_64.sh owned-loader-family --work DIR",
            _validate_loader_family,
        ),
    )
}


def publication_path(gate: str, publication: str) -> Path:
    return PUBLICATION_DIRECTORY / gate / f"{publication}.json"


def _physical_work_file(value: object, description: str) -> Path:
    """Resolve one checkout-relative regular file below ``.work`` without links."""
    if not isinstance(value, str) or not value:
        raise EvidenceUnmet(f"{description} path is invalid")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != ".work":
        raise EvidenceUnmet(f"{description} must be a checkout-relative .work path: {value}")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise EvidenceUnmet(f"{description} crosses a symlink: {value}")
    if not current.is_file():
        raise EvidenceUnmet(f"{description} is not a regular file: {value}")
    return current


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Evaluation:
    """Per-evaluation cache so one receipt is validated once for many rows."""

    def __init__(self) -> None:
        self._published: dict[tuple[str, str], Mapping[str, Any]] = {}

    def published(self, gate: str, publication_id: str) -> Mapping[str, Any]:
        key = (gate, publication_id)
        if key not in self._published:
            self._published[key] = read_publication(gate, publication_id)
        return self._published[key]


def read_publication(gate: str, publication_id: str) -> Mapping[str, Any]:
    publication = PUBLICATIONS[publication_id]
    if publication.gate != gate:
        raise GateError(f"publication {publication_id} belongs to {publication.gate}, not {gate}")
    pointer = publication_path(gate, publication_id)
    if not pointer.is_file() or pointer.is_symlink():
        raise EvidenceUnmet(
            f"no published {publication_id} receipt at {repository_relative(pointer)}; produce one with "
            f"`{publication.producer}` and select it with "
            f"`./scripts/dev-x86_64.sh qualification-manifest --publish {gate} {publication_id} RECEIPT`"
        )
    try:
        record = json.loads(pointer.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceUnmet(f"{publication_id} publication pointer is unreadable: {error}") from error
    expected_keys = {"schema", "gate", "publication", "receipt", "receipt_sha256"}
    unmet_unless(
        isinstance(record, dict)
        and set(record) == expected_keys
        and record.get("schema") == PUBLICATION_SCHEMA
        and record.get("gate") == gate
        and record.get("publication") == publication_id,
        f"{publication_id} publication pointer does not match its gate contract",
    )
    receipt = _physical_work_file(record["receipt"], f"published {publication_id} receipt")
    unmet_unless(
        receipt.name == publication.receipt_name,
        f"published {publication_id} receipt must be named {publication.receipt_name}",
    )
    unmet_unless(
        _sha256(receipt) == record["receipt_sha256"],
        f"published {publication_id} receipt bytes changed after publication",
    )
    return publication.validate(receipt)


def publish(gate: str, publication_id: str, receipt_text: str) -> Path:
    """Validate one retained receipt and atomically select it for a gate."""
    publication = PUBLICATIONS.get(publication_id)
    if publication is None or publication.gate != gate:
        known = sorted(item.id for item in PUBLICATIONS.values() if item.gate == gate)
        raise GateError(
            f"{gate} has no publication {publication_id!r}; known: {', '.join(known) or 'none'}"
        )
    candidate = Path(receipt_text)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(ROOT)
        except ValueError as error:
            raise GateError("published receipt must be below this checkout") from error
    try:
        receipt = _physical_work_file(candidate.as_posix(), f"{publication_id} receipt")
        if receipt.name != publication.receipt_name:
            raise EvidenceUnmet(f"{publication_id} receipt must be named {publication.receipt_name}")
        digest = _sha256(receipt)
        publication.validate(receipt)
        if _sha256(receipt) != digest:
            raise EvidenceUnmet(f"{publication_id} receipt changed during validation")
    except EvidenceUnmet as error:
        raise GateError(str(error)) from error
    except Exception as error:  # noqa: BLE001 - a leaf reader rejection refuses publication
        raise GateError(f"{publication_id} receipt was rejected by its reader: {type(error).__name__}: {error}") from error
    pointer = publication_path(gate, publication_id)
    pointer.parent.mkdir(parents=True, exist_ok=True)
    if pointer.parent.is_symlink() or pointer.parent.resolve() != pointer.parent:
        raise GateError("qualification evidence directory is not physical")
    value = {
        "schema": PUBLICATION_SCHEMA,
        "gate": gate,
        "publication": publication_id,
        "receipt": repository_relative(receipt),
        "receipt_sha256": digest,
    }
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=pointer.parent, prefix=".publication-", suffix=".json", delete=False
    ) as output:
        staged = Path(output.name)
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    try:
        os.chmod(staged, 0o644)
        os.replace(staged, pointer)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return pointer


POSIX_NATIVE_COMMAND = (
    "./scripts/dev-x86_64.sh owned-posix-native --family-execution FILE --crypt-profile FILE "
    "--atomic-addressable-profile FILE --wordexp-profile FILE --wordexp-expected-native-inputs FILE "
    "--output NEW_DIR"
)
POSIX_PROCESS_COMPONENTS = ("differential", "os-test", "signal-process", "pthread-stress", "libc-test")


def _read_posix_process(evaluation: Evaluation) -> str:
    record = evaluation.published("compat.posix-process", "posix-native")
    components = record.get("components")
    unmet_unless(
        isinstance(components, Mapping) and tuple(components) == POSIX_PROCESS_COMPONENTS,
        "native POSIX receipt does not carry the complete ordered "
        + "/".join(POSIX_PROCESS_COMPONENTS)
        + " roster",
    )
    unmet_unless(
        record.get("status") == "native-aggregate-verified" and record.get("native_aggregate_complete") is True,
        "native POSIX receipt is not a complete native aggregate",
    )
    return "published native aggregate: " + ", ".join(POSIX_PROCESS_COMPONENTS)


RESOLVER_NETWORK_REPORT = ROOT / "compat" / "reports" / "resolver-network" / "x86_64" / "latest.json"


def _read_resolver_network(evaluation: Evaluation) -> str:
    del evaluation
    unmet_unless(
        RESOLVER_NETWORK_REPORT.is_file() and not RESOLVER_NETWORK_REPORT.is_symlink(),
        f"no passing resolver-network report at {repository_relative(RESOLVER_NETWORK_REPORT)}; "
        "produce it with `./scripts/dev-x86_64.sh owned-resolver-network`",
    )
    report = _import_compat("resolver_network_component_receipt").validate_report(ROOT, RESOLVER_NETWORK_REPORT)
    unmet_unless(report.get("passed") is True, "resolver-network report did not pass")
    return "resolver-network physical receipt: two arms, twelve candidate modes"


LOADER_CORPUS_ROWS = {
    "./scripts/dev-x86_64.sh owned-loader-synthetic DYNAMIC_SYSROOT": "synthetic-loader-catalog",
    "./scripts/dev-x86_64.sh owned-package-corpus --dynamic-sysroot DYNAMIC_SYSROOT": "frozen-package-corpus",
}
LOADER_PRODUCTS = ("installed", "second", "extracted")


def _loader_family_record(evaluation: Evaluation) -> Mapping[str, Any]:
    record = evaluation.published("compat.loader-corpus", "loader-family")
    unmet_unless(
        record.get("status") == "installed-loader-component-verified" and record.get("component_complete") is True,
        "loader-family receipt is not a complete installed loader component",
    )
    return record


def _loader_row_reader(row: str) -> Callable[[Evaluation], str]:
    def read(evaluation: Evaluation) -> str:
        coverage = _loader_family_record(evaluation).get("coverage")
        unmet_unless(isinstance(coverage, Mapping) and isinstance(coverage.get(row), Mapping),
                     f"loader-family receipt has no {row} coverage row")
        cells = coverage[row].get("cells")
        unmet_unless(isinstance(cells, Mapping) and tuple(cells) == LOADER_PRODUCTS,
                     f"loader-family {row} row does not cover {'/'.join(LOADER_PRODUCTS)} products")
        return f"published loader-family receipt: {row} across {'/'.join(LOADER_PRODUCTS)}"

    return read


def _read_loader_inventory(evaluation: Evaluation) -> str:
    inputs = _loader_family_record(evaluation).get("inputs")
    before = inputs.get("before") if isinstance(inputs, Mapping) else None
    inventories = before.get("inventories") if isinstance(before, Mapping) else None
    unmet_unless(isinstance(inventories, Mapping) and tuple(inventories) == LOADER_PRODUCTS,
                 "loader-family receipt does not bind one retained inventory per product")
    return f"published loader-family receipt: retained inventories for {'/'.join(LOADER_PRODUCTS)}"


def _read_loader_family(evaluation: Evaluation) -> str:
    _loader_family_record(evaluation)
    return "published loader-family receipt: complete three-product component"


STATIC_C_ABI_DIFFERENTIAL_RUNNER = "compat/x86_64/run_libc_static_c_abi_differential.sh"
STATIC_C_ABI_DIFFERENTIAL_MARKER = b"x86 static C ABI differential bootstrap: PASS (libc.a; pinned musl 1.2.6)"
EXECUTION_TIMEOUT_SECONDS = 3600


def _execute_static_c_abi_differential(evaluation: Evaluation) -> str:
    del evaluation
    try:
        completed = subprocess.run(
            ["bash", STATIC_C_ABI_DIFFERENTIAL_RUNNER],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=EXECUTION_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise EvidenceUnmet(f"{STATIC_C_ABI_DIFFERENTIAL_RUNNER} timed out after {EXECUTION_TIMEOUT_SECONDS}s") from error
    lines = [line for line in completed.stdout.splitlines() if line]
    if completed.returncode != 0 or not lines or lines[-1] != STATIC_C_ABI_DIFFERENTIAL_MARKER:
        tail = (completed.stderr or completed.stdout).decode("utf-8", errors="replace").strip().splitlines()[-5:]
        raise EvidenceUnmet(
            f"{STATIC_C_ABI_DIFFERENTIAL_RUNNER} exited {completed.returncode} without its completion marker: "
            + " | ".join(tail)
        )
    return STATIC_C_ABI_DIFFERENTIAL_MARKER.decode("utf-8")


def _read_lua_source_build(evaluation: Evaluation) -> str:
    del evaluation
    directory = str(ROOT / "compat" / "lua")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import source_build_admission

    result = source_build_admission.validate()
    return "current-source Lua static and dynamic reports admitted: " + ", ".join(sorted(result))


def _read_parity_ledger(evaluation: Evaluation) -> str:
    del evaluation
    ledger = _import_compat("validate_parity_ledger")
    inventory = _import_compat("aarch64_parity_inventory")
    report = ledger.validate_ledger(ledger.load_toml(ledger.LEDGER_PATH))
    inventory.validate_frozen_baseline()
    inventory.validate_inventory()
    return f"frozen baseline, ledger ({report['family_count']} families) and derived inventory validate"


READERS: dict[tuple[str, str], EvidenceReader] = {
    (reader.gate, reader.command): reader
    for reader in (
        EvidenceReader(
            "compat.abi-differential",
            "./scripts/dev-x86_64.sh libc-static-c-abi-differential",
            "execution",
            STATIC_C_ABI_DIFFERENTIAL_RUNNER,
            _execute_static_c_abi_differential,
        ),
        EvidenceReader(
            "compat.posix-process",
            POSIX_NATIVE_COMMAND,
            "publication",
            "posix-native",
            _read_posix_process,
        ),
        EvidenceReader(
            "compat.resolver-network",
            "./scripts/dev-x86_64.sh owned-resolver-network",
            "report",
            repository_relative(RESOLVER_NETWORK_REPORT),
            _read_resolver_network,
        ),
        *(
            EvidenceReader("compat.loader-corpus", command, "publication", "loader-family", _loader_row_reader(row))
            for command, row in LOADER_CORPUS_ROWS.items()
        ),
        EvidenceReader(
            "compat.loader-corpus",
            "./scripts/dev-x86_64.sh owned-loader-inventory DYNAMIC_SYSROOT OUTPUT_JSON",
            "publication",
            "loader-family",
            _read_loader_inventory,
        ),
        EvidenceReader(
            "compat.loader-corpus",
            "./scripts/dev-x86_64.sh owned-loader-family --work DIR",
            "publication",
            "loader-family",
            _read_loader_family,
        ),
        EvidenceReader(
            "consumer.source-build",
            "./scripts/dev-x86_64.sh lua-source-build-admission",
            "report",
            "compat/lua/source_build_admission.py",
            _read_lua_source_build,
        ),
        EvidenceReader(
            "capability.accounting",
            "python3 compat/x86_64/validate_parity_ledger.py",
            "ledger",
            "compat/x86_64/validate_parity_ledger.py",
            _read_parity_ledger,
        ),
    )
}


# ---------------------------------------------------------------------------
# Gate-specific completion checks


def _capability_completion(families: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Every frozen capability must be complete; name each one that is not."""
    del families
    inventory = _import_compat("aarch64_parity_inventory").build_inventory()
    incomplete: dict[str, dict[str, list[str]]] = {}
    for row in inventory["capabilities"]:
        state = row["contract_state"]
        if state != "implemented-foundation":
            incomplete.setdefault(row["x86_family"], {}).setdefault(state, []).append(row["id"])
    count = sum(len(ids) for states in incomplete.values() for ids in states.values())
    return {
        "id": "capability-completion",
        "met": not incomplete,
        "detail": (
            f"all {len(inventory['capabilities'])} frozen capabilities are implemented-foundation"
            if not incomplete
            else {"incomplete_capability_count": count, "by_family": incomplete}
        ),
    }


GATE_CHECKS: dict[str, tuple[Callable[[Mapping[str, Mapping[str, Any]]], dict[str, Any]], ...]] = {
    "capability.accounting": (_capability_completion,),
}


# ---------------------------------------------------------------------------
# Evaluation


def _prerequisite_condition(gate: str, families: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    unmet = [
        {"family": family, "status": families[family].get("status"), "required_by": reason}
        for family, reason in prerequisite_families(gate, families)
        if families[family].get("status") != COMPLETED_STATUS
    ]
    return {
        "id": "prerequisite-families",
        "met": not unmet,
        "detail": unmet if unmet else "every prerequisite family is foundation-verified",
    }


def _evidence_condition(
    gate: str,
    index: int,
    entry: Mapping[str, Any],
    evaluation: Evaluation | None,
) -> dict[str, Any]:
    command = entry.get("command")
    condition: dict[str, Any] = {
        "id": f"evidence[{index}]",
        "command": command,
        "ledger_state": entry.get("state"),
    }
    reader = READERS.get((gate, command)) if isinstance(command, str) else None
    if reader is None:
        executable = isinstance(command, str) and (command.startswith("./") or command.startswith("python3 "))
        condition.update(
            met=False,
            detail=(
                "no qualification reader is registered for this evidence command"
                if executable
                else "ledger evidence is a prose placeholder, not an executable command with a qualification reader"
            ),
        )
        return condition
    condition.update(reader=reader.kind, source=reader.source)
    if evaluation is None:
        condition.update(met=None, detail="read natively by ./scripts/dev-x86_64.sh qualification-manifest")
        return condition
    try:
        condition.update(met=True, detail=reader.read(evaluation))
    except EvidenceUnmet as error:
        condition.update(met=False, detail=str(error))
    except Exception as error:  # noqa: BLE001 - every reader failure is a named unmet condition
        condition.update(met=False, detail=f"{type(error).__name__}: {error}")
    return condition


def source_state() -> dict[str, Any]:
    """Return the checkout's revision and every uncommitted path, if any."""
    environment = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}

    def git(*arguments: str) -> str:
        try:
            return subprocess.run(
                ["git", "-c", f"safe.directory={ROOT}", *arguments],
                cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, capture_output=True,
                check=True, text=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as error:
            raise GateError(f"cannot read checkout source state: {error}") from error

    return {
        "revision": git("rev-parse", "HEAD").strip(),
        "uncommitted": git("status", "--porcelain", "--untracked-files=all").splitlines(),
    }


def _clean_source_condition(state: Mapping[str, Any]) -> dict[str, Any]:
    uncommitted = list(state["uncommitted"])
    return {
        "id": "clean-committed-source",
        "met": not uncommitted,
        "detail": (
            f"clean revision {state['revision']}"
            if not uncommitted
            else {"revision": state["revision"], "uncommitted": uncommitted[:20], "count": len(uncommitted)}
        ),
    }


def _source_unchanged_condition(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    unchanged = dict(before) == dict(after)
    return {
        "id": "source-unchanged",
        "met": unchanged,
        "detail": "source state is identical after every read" if unchanged else {"before": before, "after": after},
    }


def evaluate(gate: str, *, native: bool) -> dict[str, Any]:
    """Return every condition of one gate; ``passed`` only after native reads.

    Native evaluation also requires clean committed source before any read
    and the identical source state afterwards, so no reader can validate
    evidence against uncommitted or concurrently edited bytes. Execution
    readers are costly and are attempted only after every other condition of
    the gate is met. Their row names that deferral otherwise.
    """
    if gate not in CHAIN:
        raise GateError(f"unknown qualification gate: {gate}")
    families = load_families()
    family = families[gate]
    evidence = family.get("native_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise GateError(f"gate family {gate} has no native evidence")
    evaluation = Evaluation() if native else None
    source_before = source_state() if native else None
    conditions = [_prerequisite_condition(gate, families)]
    if source_before is not None:
        conditions.insert(0, _clean_source_condition(source_before))
    deferred: list[tuple[int, Mapping[str, Any]]] = []
    evidence_rows: dict[int, dict[str, Any]] = {}
    for index, entry in enumerate(evidence):
        if not isinstance(entry, Mapping):
            raise GateError(f"gate family {gate} native evidence entry {index} is invalid")
        reader = READERS.get((gate, entry.get("command")))
        if native and reader is not None and reader.kind == "execution":
            deferred.append((index, entry))
            continue
        evidence_rows[index] = _evidence_condition(gate, index, entry, evaluation)
    checks = [check(families) for check in GATE_CHECKS.get(gate, ())]
    blocked = any(row["met"] is not True for row in (*conditions, *evidence_rows.values(), *checks))
    for index, entry in deferred:
        if blocked:
            reader = READERS[(gate, entry["command"])]
            evidence_rows[index] = {
                "id": f"evidence[{index}]",
                "command": entry.get("command"),
                "ledger_state": entry.get("state"),
                "reader": reader.kind,
                "source": reader.source,
                "met": None,
                "detail": "not executed: the gate already has unmet conditions",
            }
        else:
            evidence_rows[index] = _evidence_condition(gate, index, entry, evaluation)
    conditions.extend(evidence_rows[index] for index in sorted(evidence_rows))
    conditions.extend(checks)
    if source_before is not None:
        conditions.append(_source_unchanged_condition(source_before, source_state()))
    unmet = [row["id"] for row in conditions if row["met"] is not True]
    return {
        "schema": CONDITIONS_SCHEMA,
        "gate": gate,
        "native": native,
        "passed": native and not unmet,
        "unmet": unmet,
        "conditions": conditions,
    }


def evaluate_chain(*, native: bool) -> list[dict[str, Any]]:
    """Evaluate every gate independently; this is a diagnostic, not a chain."""
    return [evaluate(gate, native=native) for gate in CHAIN]


def main(arguments: Sequence[str] | None = None) -> int:
    """Pinned case entry: evaluate one gate natively and print its record."""
    values = list(sys.argv[1:] if arguments is None else arguments)
    if len(values) != 1 or values[0] not in CHAIN:
        print("usage: run_qualification_gate.py GATE", file=sys.stderr)
        return 2
    gate = values[0]
    # The case interpreter itself starts with PYTHONSAFEPATH=1. Leaf readers
    # may start their own script entry points, which import script-directory
    # siblings; do not impose this interpreter's import policy on them.
    os.environ.pop("PYTHONSAFEPATH", None)
    try:
        result = evaluate(gate, native=True)
    except GateError as error:
        print(f"x86 qualification gate {gate}: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["passed"]:
        print(pass_marker(gate))
        return 0
    print(f"x86 qualification gate {gate}: UNMET ({', '.join(result['unmet'])})")
    return 1
