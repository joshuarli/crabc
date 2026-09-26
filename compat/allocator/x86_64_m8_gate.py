#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for owned-libc allocator integration.

The required rows cover startup, threads, C ABI, interposition, static and
dynamic products, loader, Rust std, Lua, and the selected program corpus.
The evidence registry names each row's native-shadow product commands.

Every evidence entry is an existing `scripts/dev-x86_64.sh` product command.
One entry, named by the contract's `products` record, builds the native-shadow
static and dynamic sysroots; the entries that consume supplied products
receive them through the `{static_sysroot}`/`{dynamic_sysroot}` placeholders,
bound from that entry's printed evidence directory. A consumer whose products
were not built does not run and is recorded as failed.

A gate passes only when it carries no reviewed blocker and every evidence
entry has a command that executed successfully on this run. The Rust std row
also rereads its source-bound receipt, product snapshots, and retained files.
Evidence without a command is declared missing, and a gate that depends on it
must name a blocker. Runnable evidence is always executed; its pass never
removes a blocker by itself.

The product commands start their own containers, so this runner executes on
the native x86-64 host, not inside the allocator evidence image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness

sys.path.insert(0, str(harness.ROOT / "compat/x86_64"))
import consumer_rust_std_lto as consumer
import owned_dynamic_qualification as qualification


CONTRACT = harness.ALLOCATOR_ROOT / "m8-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m8-gate"
GATE_IDS = (
    "m8.startup-constructors",
    "m8.threads-fork",
    "m8.errno-c-abi",
    "m8.weak-interposed",
    "m8.static-dynamic-products",
    "m8.dso-loader",
    "m8.rust-std",
    "m8.lua",
    "m8.corpus",
)
PRODUCT_PLACEHOLDERS = ("{static_sysroot}", "{dynamic_sysroot}")
DISPATCHER = "scripts/dev-x86_64.sh"
EVIDENCE_TIMEOUT_SECONDS = 7200
# The dispatcher's container sees the checkout at this path.
CONTAINER_ROOT = Path("/workspace")
ARTIFACTS = harness.ROOT / ".work/allocator-x86_64/reports/allocator/x86_64/m8-gate"


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M8 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def _uses_products(command: Sequence[str]) -> bool:
    return any(placeholder in argument for argument in command for placeholder in PRODUCT_PLACEHOLDERS)


def validate_contract(contract: Mapping[str, Any], pin: Mapping[str, str]) -> dict[str, Any]:
    """Validate the evidence registry and gate honesty without claiming a pass."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M8 allocator gate contract")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M8 allocator gate upstream identity mismatch")

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M8 allocator gate lacks an evidence registry")
    products = contract.get("products")
    if not isinstance(products, Mapping) or set(products) != {
        "evidence", "evidence_line", "static_sysroot", "dynamic_sysroot",
    } or not all(isinstance(value, str) and value for value in products.values()):
        raise harness.HarnessError("M8 products record must name its evidence, line prefix, and sysroot names")
    runnable: dict[str, list[str]] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or set(record) != {"command", "scope"}:
            raise harness.HarnessError(f"M8 evidence {evidence_id} must record exactly command and scope")
        if not isinstance(record["scope"], str) or not record["scope"]:
            raise harness.HarnessError(f"M8 evidence {evidence_id} lacks a scope")
        command = record["command"]
        if command is None:
            continue
        command = _string_list(command, f"evidence {evidence_id} command")
        if len(command) < 2 or command[0] != DISPATCHER or not (harness.ROOT / command[0]).is_file():
            raise harness.HarnessError(f"M8 evidence {evidence_id} must be a {DISPATCHER} product command")
        runnable[evidence_id] = command
    producer = products["evidence"]
    if producer not in runnable:
        raise harness.HarnessError("M8 products evidence must be runnable")
    if _uses_products(runnable[producer]):
        raise harness.HarnessError("M8 products evidence cannot consume its own products")

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M8 allocator gate order or identity changed")
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M8 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M8 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M8 gate {gate_id} lacks an acceptance contract")
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M8 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M8 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M8 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "products": dict(products),
        "runnable_evidence": runnable,
    }


def gate_report(
    contract: Mapping[str, Any], summary: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Classify each gate from reviewed blockers and executed evidence."""

    records: list[dict[str, Any]] = []
    for gate in contract["gates"]:
        observed = {entry: results[entry]["status"] for entry in gate["evidence"] if entry in results}
        missing = [entry for entry in gate["evidence"] if entry not in summary["runnable_evidence"]]
        if any(status != "passed" for status in observed.values()):
            status = "failed"
        elif gate["blocked_by"] or missing or len(observed) != len(gate["evidence"]):
            status = "blocked"
        else:
            status = "passed"
        records.append({
            "blocked_by": list(gate["blocked_by"]),
            "evidence": observed,
            "id": gate["id"],
            "missing_evidence": missing,
            "status": status,
        })
    unmet = [record["id"] for record in records if record["status"] != "passed"]
    return {
        "contract": harness.relative(CONTRACT),
        "evidence": {key: dict(value) for key, value in sorted(results.items())},
        "gates": records,
        "overall_status": "passed" if not unmet else "unmet",
        "unmet_required": unmet,
    }


def product_directory(output: str, line_prefix: str) -> str | None:
    """The evidence directory the products command printed, if exactly one."""

    found = [line[len(line_prefix):].strip() for line in output.splitlines() if line.startswith(line_prefix)]
    if len(found) != 1 or not found[0].startswith(f"{CONTAINER_ROOT}/"):
        return None
    return found[0]


def bind_products(command: Sequence[str], products: Mapping[str, str], directory: str) -> list[str]:
    """Replace the sysroot placeholders with the built products' container paths."""

    static = f"{directory}/{products['static_sysroot']}"
    dynamic = f"{directory}/{products['dynamic_sysroot']}"
    return [
        argument.replace("{static_sysroot}", static).replace("{dynamic_sysroot}", dynamic)
        for argument in command
    ]


def ordered_evidence(runnable: Mapping[str, Sequence[str]], producer: str) -> list[str]:
    """The products command first, then every other entry in contract order."""

    return [producer, *(entry for entry in runnable if entry != producer)]


def read_native_shadow_receipt(command: Sequence[str], expected_source: str) -> dict[str, str]:
    """Bind the completed consumer to current source, its products, and retained bytes."""

    def argument(option: str) -> str:
        positions = [index for index, value in enumerate(command) if value == option]
        if len(positions) != 1 or positions[0] + 1 >= len(command):
            raise harness.HarnessError(f"Rust std consumer must supply one {option}")
        return command[positions[0] + 1]

    def checkout_path(path: str) -> Path:
        candidate = Path(path)
        try:
            relative = candidate.relative_to(CONTAINER_ROOT / ".work")
        except ValueError as error:
            raise harness.HarnessError(f"Rust std receipt path escapes checkout work: {path}") from error
        host = harness.ROOT / ".work" / relative
        if not host.exists() or host.is_symlink() or host.resolve() != host:
            raise harness.HarnessError(f"Rust std receipt path is missing or not physical: {path}")
        return host

    def checkout_file(path: str) -> Path:
        host = checkout_path(path)
        if not host.is_file():
            raise harness.HarnessError(f"Rust std receipt file is missing: {path}")
        return host

    if argument("--allocator-evidence") != "native-shadow":
        raise harness.HarnessError("Rust std consumer did not select native-shadow evidence")
    roots = {
        "static": argument("--development-static-sysroot"),
        "dynamic": argument("--development-dynamic-sysroot"),
    }
    receipt_path = checkout_file(f"{argument('--output')}/receipt.json")
    try:
        record = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise harness.HarnessError(f"Rust std receipt cannot be read: {error}") from error
    if not isinstance(record, dict) or any((
        record.get("schema") != consumer.SCHEMA,
        record.get("gate") != consumer.GATE,
        record.get("source_sha256") != expected_source,
        record.get("allocator_evidence") != "native-shadow",
        record.get("qualifying") is not False,
        record.get("cohort") is not None,
        record.get("passed") is not True,
        record.get("unmet_conditions") != [],
    )):
        raise harness.HarnessError("Rust std receipt status or current source does not match native-shadow evidence")
    gates = record.get("gates")
    if (record.get("frozen_gates") != list(consumer.FROZEN_GATES)
            or not isinstance(gates, dict) or set(gates) != set(consumer.FROZEN_GATES)
            or any(not isinstance(gate, dict) or not isinstance(gate.get("lanes"), dict)
                   or not gate["lanes"] or any(not isinstance(lane, dict) or lane.get("unmet") != []
                                              for lane in gate["lanes"].values())
                   for gate in gates.values())):
        raise harness.HarnessError("Rust std receipt lacks a frozen consumer gate")
    unwind = record.get("unwind")
    if (not isinstance(unwind, dict) or set(unwind) != {"native-shadow"}
            or not isinstance(unwind["native-shadow"], dict)
            or unwind["native-shadow"].get("unmet") != []
            or not isinstance(unwind["native-shadow"].get("cross_dso"), dict)
            or set(unwind["native-shadow"]["cross_dso"]) != {"stock-std", "build-std"}
            or any(not isinstance(lane, dict) or lane.get("unmet") != []
                   for lane in unwind["native-shadow"]["cross_dso"].values())):
        raise harness.HarnessError("Rust std receipt lacks the unwind and cross-DSO matrix")
    regressions = record.get("provider_regressions")
    if (not isinstance(regressions, dict) or not isinstance(regressions.get("lanes"), dict)
            or set(regressions["lanes"]) != set(consumer.PROVIDER_REGRESSIONS)
            or any(not isinstance(lane, dict) or lane.get("unmet") != []
                   for lane in regressions["lanes"].values())):
        raise harness.HarnessError("Rust std receipt lacks the provider regressions")
    products = record.get("products")
    if not isinstance(products, dict) or set(products) != {"native-shadow"}:
        raise harness.HarnessError("Rust std receipt lacks the native-shadow products")
    pair = products["native-shadow"]
    if not isinstance(pair, dict) or pair.get("label") != "native-shadow":
        raise harness.HarnessError("Rust std receipt product pair is malformed")
    for mode, container_root in roots.items():
        snapshot = pair.get(mode)
        if not isinstance(snapshot, dict) or snapshot.get("root") != container_root:
            raise harness.HarnessError(f"Rust std receipt {mode} product does not match the supplied root")
        host_root = checkout_path(container_root)
        if not host_root.is_dir():
            raise harness.HarnessError(f"Rust std receipt {mode} product root is missing")
        try:
            current = consumer.owned_cleanup.product_snapshot(host_root, mode)
            backend = consumer.product_allocator_backend(host_root, mode)
        except (consumer.owned_cleanup.OwnedCleanupError, OSError, ValueError) as error:
            raise harness.HarnessError(f"Rust std receipt {mode} product cannot be reread: {error}") from error
        manifest = snapshot.get("manifest")
        if (backend != "native-shadow" or snapshot.get("files") != current["files"]
                or not isinstance(manifest, dict)
                or manifest.get("path") != str(CONTAINER_ROOT / current["manifest"]["path"]
                                               .removeprefix(str(harness.ROOT) + "/"))
                or manifest.get("sha256") != current["manifest"]["sha256"]):
            raise harness.HarnessError(f"Rust std receipt {mode} product changed")
        if mode == "dynamic":
            state_path = checkout_file(f"{container_root}/share/crabc/dynamic-product-state.json")
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise harness.HarnessError(f"Rust std dynamic product state cannot be read: {error}") from error
            if (not isinstance(state, dict) or state.get("source_sha256") != expected_source
                    or state.get("allocator_backend") != "native-shadow"):
                raise harness.HarnessError("Rust std receipt dynamic product source does not match")
    retained = record.get("retained_files")
    if not isinstance(retained, dict) or not retained:
        raise harness.HarnessError("Rust std receipt retains no files")
    toolchain = record.get("toolchain", {})
    if not isinstance(toolchain, dict):
        raise harness.HarnessError("Rust std receipt toolchain identity is malformed")
    toolchain_files = {
        item["path"]: item["sha256"] for item in toolchain.values()
        if isinstance(item, dict) and "path" in item and "sha256" in item
    }
    for path, digest in retained.items():
        if not isinstance(path, str) or not isinstance(digest, str):
            raise harness.HarnessError("Rust std retained file identity is malformed")
        if path in toolchain_files:
            # Toolchain files exist only inside the pinned evidence image; the
            # consumer hashed them during execution. Recheck their recorded
            # identity here and rehash every checkout-owned retained file.
            sysroot = toolchain.get("sysroot")
            if not isinstance(sysroot, str) or not Path(path).is_relative_to(sysroot):
                raise harness.HarnessError(f"Rust std retained toolchain path escaped its sysroot: {path}")
            if toolchain_files[path] != digest:
                raise harness.HarnessError(f"Rust std retained toolchain identity changed: {path}")
            continue
        file = checkout_file(path)
        if consumer.sha256_file(file) != digest:
            raise harness.HarnessError(f"Rust std retained file changed: {path}")
    return {
        "path": harness.relative(receipt_path),
        "sha256": consumer.sha256_file(receipt_path),
        "source_sha256": expected_source,
    }


def run_evidence(
    runnable: Mapping[str, Sequence[str]], products: Mapping[str, str], selected: Sequence[str], artifacts: Path,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    directory: str | None = None
    producer = products["evidence"]
    for evidence_id in ordered_evidence(runnable, producer):
        command = runnable[evidence_id]
        needs_products = _uses_products(command)
        if evidence_id not in selected and not (evidence_id == producer and any(
            _uses_products(runnable[entry]) for entry in selected
        )):
            continue
        log = artifacts / f"{evidence_id.replace(':', '-')}.log"
        if needs_products:
            if directory is None:
                log.write_text(f"not run: {producer} did not provide native-shadow products\n")
                results[evidence_id] = {"command": list(command), "log": harness.relative(log), "status": "failed"}
                continue
            command = bind_products(command, products, directory)
        record = harness.command_record(
            [str(harness.ROOT / command[0]), *command[1:]], cwd=harness.ROOT,
            timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
        )
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        passed = record["status"] == 0
        if evidence_id == producer and passed:
            directory = product_directory(str(record["stdout"]) + str(record["stderr"]), products["evidence_line"])
            passed = directory is not None
        receipt: dict[str, str] | None = None
        if evidence_id == "consumer:rust-std-lto" and passed:
            try:
                receipt = read_native_shadow_receipt(command, qualification.source_digest())
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"M8 receipt reader: {error}\n")
                passed = False
        if evidence_id in selected:
            results[evidence_id] = {
                "command": list(command),
                "log": harness.relative(log),
                "status": "passed" if passed else "failed",
            }
            if receipt is not None:
                results[evidence_id]["receipt"] = receipt
    return results


def load_summary() -> tuple[dict[str, Any], dict[str, Any]]:
    contract = harness.read_json(CONTRACT)
    return contract, validate_contract(contract, harness.load_pin())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
        help="validate the contract without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS, help="execute only this gate's runnable evidence")
    arguments = parser.parse_args(argv)
    contract, summary = load_summary()
    if arguments.check:
        print(
            f"M8 gate contract valid: {len(summary['gate_ids'])} gates; "
            f"{len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    runnable = summary["runnable_evidence"]
    selected = list(runnable)
    if arguments.gate is not None:
        gate = next(entry for entry in contract["gates"] if entry["id"] == arguments.gate)
        selected = [entry for entry in gate["evidence"] if entry in runnable]
        contract = {**contract, "gates": [gate]}
    report = gate_report(contract, summary, run_evidence(runnable, summary["products"], selected, ARTIFACTS))
    report_path = ARTIFACTS / ("report.json" if arguments.gate is None else f"{arguments.gate}.json")
    harness.write_json(report_path, report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
        for evidence_id, status in record["evidence"].items():
            print(f"  {evidence_id}: {status}")
        for blocker in record["blocked_by"]:
            print(f"  blocked: {blocker}")
        for evidence_id in record["missing_evidence"]:
            print(f"  missing: {evidence_id}")
    if report["overall_status"] != "passed":
        print(
            f"M8 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(report_path)}",
            file=sys.stderr,
        )
        return 1
    print("M8 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
