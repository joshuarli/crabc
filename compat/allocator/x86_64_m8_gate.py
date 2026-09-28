#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for owned-libc allocator integration.

The required rows cover startup, threads, C ABI, interposition, static and
dynamic products, loader, Rust std, Lua, and the selected program corpus.
The evidence registry names each row's native-shadow product commands. The
Lua and corpus rows reread their private reports inside the pinned image.

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
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness

sys.path.insert(0, str(harness.ROOT / "compat/x86_64"))
import consumer_rust_std_lto as consumer
import owned_dynamic_qualification as qualification
import native_shadow_receipt
import owned_mimalloc_startup_errno_receipt as startup_errno
import owned_native_allocator_policy_receipt as policy_reader


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
CORE_IMAGE = "crabc-core-evidence:x86_64"


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


def read_native_allocator_policy_receipt(command: Sequence[str], output: str) -> dict[str, Any]:
    """Bind the allocator-policy transcript matrix to the sysroots it supplies."""

    runner = "owned-native-allocator-policy"
    if list(command) != [DISPATCHER, runner]:
        raise harness.HarnessError("native allocator policy used non-canonical arguments")
    evidence = product_directory(output, "native-allocator-policy evidence: ")
    if evidence is None:
        raise harness.HarnessError("native allocator policy did not emit one evidence directory")
    try:
        relative = Path(evidence).relative_to(CONTAINER_ROOT / ".work/x86_64/tmp")
        if len(relative.parts) != 1 or not relative.name.startswith(f"{runner}."):
            raise harness.HarnessError("native allocator policy evidence escaped its runner root")
        work = consumer.owned_cleanup.work_child(
            harness.ROOT / ".work/x86_64/tmp" / relative, "native allocator policy evidence", existing=True)
        receipt = policy_reader.read_policy_receipt(harness.ROOT)
        raw = json.loads(receipt.path.read_text(encoding="utf-8"))
        if raw.get("work") != work.relative_to(harness.ROOT).as_posix():
            raise harness.HarnessError("native allocator policy receipt names another execution root")
        static = work / "static-sysroot"
        dynamic = work / "dynamic-sysroot"
        consumer.owned_cleanup.product_snapshot(static, "static")
        consumer.owned_cleanup.product_snapshot(dynamic, "dynamic")
        originals = {
            "static-manifest": static / "share/crabc/manifest.json",
            "static-libc-provenance": static / "share/crabc/libc-static.provenance.json",
            "static-libc-archive": static / "usr/lib/libc.a",
            "static-driver": static / "bin/crabc-cc",
            "static-crt1": static / "usr/lib/crt1.o",
            "static-rcrt1": static / "usr/lib/rcrt1.o",
            "static-crti": static / "usr/lib/crti.o",
            "static-crtn": static / "usr/lib/crtn.o",
            "static-builtins": static / "usr/lib/libcrabc-builtins.a",
            "dynamic-manifest": dynamic / "share/crabc/manifest.json",
            "dynamic-product-state": dynamic / "share/crabc/dynamic-product-state.json",
            "dynamic-libc-provenance": dynamic / "share/crabc/libc-shared.provenance.json",
            "dynamic-libc": dynamic / "usr/lib/libc.so",
            "dynamic-loader": dynamic / "lib/ld-crabc-x86_64.so.1",
            "dynamic-driver": dynamic / "bin/crabc-cc-dynamic",
            "dynamic-crt1": dynamic / "usr/lib/crt1.o",
            "dynamic-scrt1": dynamic / "usr/lib/Scrt1.o",
            "dynamic-crti": dynamic / "usr/lib/crti.o",
            "dynamic-crtn": dynamic / "usr/lib/crtn.o",
            "dynamic-attach": dynamic / "usr/lib/crabc-dynamic-attach.o",
            "dynamic-builtins": dynamic / "usr/lib/libcrabc-builtins.a",
        }
        for name, original in originals.items():
            original = consumer.owned_cleanup.physical(original, f"native allocator policy {name}")
            if {"sha256": consumer.owned_cleanup.digest(original),
                    "size": original.stat().st_size} != receipt.products[name]:
                raise harness.HarnessError(f"native allocator policy original product changed: {name}")
        state = json.loads(originals["dynamic-product-state"].read_text(encoding="utf-8"))
        static_manifest = json.loads(originals["static-manifest"].read_text(encoding="utf-8"))
        dynamic_provenance = json.loads(originals["dynamic-libc-provenance"].read_text(encoding="utf-8"))
        source_sha256 = qualification.source_digest()
        if (static_manifest.get("allocator_backend") != "native-shadow"
                or dynamic_provenance.get("allocator_backend") != "native-shadow"
                or state.get("allocator_backend") != "native-shadow"
                or state.get("source_sha256") != source_sha256):
            raise harness.HarnessError("native allocator policy product is not current native-shadow source")
        return {"path": str(receipt.path), "sha256": consumer.sha256_file(receipt.path),
                "source": dict(receipt.source), "source_sha256": source_sha256,
                "products": {mode: consumer.sha256_file(root / "share/crabc/manifest.json")
                             for mode, root in (("static", static), ("dynamic", dynamic))},
                "case_count": len(receipt.cases)}
    except (native_shadow_receipt.ReceiptError, consumer.owned_cleanup.OwnedCleanupError,
            qualification.QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        raise harness.HarnessError(f"native allocator policy physical receipt is invalid: {error}") from error


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


def read_lua_evidence(lane: str, report_path: Path) -> dict[str, Any]:
    """Reread one private Lua report and all of its source, workload, and product bytes."""

    if lane not in {"static", "dynamic"}:
        raise harness.HarnessError("Lua receipt lane must be static or dynamic")
    # Both Lua readers import their sibling module named `run`; replace the
    # allocator runner's import only in this short-lived reader process.
    sys.modules.pop("run", None)
    sys.path.insert(0, str(harness.ROOT / "compat/lua"))
    import run as lua
    import run_x86_dynamic as dynamic
    import source_build_admission as admission

    expected_parent = harness.ROOT / ".work/x86_64" / f"lua-{lane}-source-build-native-shadow"
    report_path = Path(report_path)
    try:
        state = lua.require_physical_directory(report_path.parent, "native-shadow Lua state")
        report_path = lua.require_physical_regular_file(report_path, "native-shadow Lua report")
        if state.parent != expected_parent or not state.name.startswith("run-") or report_path != state / "report.json":
            raise harness.HarnessError("Lua private report escaped its native-shadow state root")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        runner = ("crabc-lua-native-x86-static-source-build" if lane == "static"
                  else "crabc-lua-native-x86-dynamic-source-build-dispatch")
        if (not isinstance(report, dict) or report.get("runner") != runner
                or report.get("passed") is not True or report.get("result") != "pass"):
            raise harness.HarnessError("Lua private report did not pass its source-build runner")
        dispatcher = report.get("dispatcher")
        source = lua.current_source_identity()
        if (not isinstance(dispatcher, dict) or dispatcher.get("state_root") != str(state)
                or dispatcher.get("authoritative_report") != str(report_path)
                or dispatcher.get("latest_report") is not None
                or dispatcher.get("allocator_backend") != "native-shadow"
                or dispatcher.get("source_identity") != source):
            raise harness.HarnessError("Lua private report is not bound to current native-shadow source")
        admission.validate_report_records(report)
        products: dict[str, str] = {}
        if lane == "static":
            admission.validate_pinned_input(report)
            root, _wrapper, _runtime, manifest = lua.owned_static_sysroot(state / "sysroot")
            environment = report.get("environment")
            modes = report.get("modes")
            if (manifest.get("allocator_backend") != "native-shadow"
                    or not isinstance(environment, dict)
                    or environment.get("sysroot_manifest") != manifest
                    or not isinstance(modes, dict)
                    or set(modes) != {"static-et-exec", "static-pie"}):
                raise harness.HarnessError("Lua static report or installed product changed")
            for name, row in modes.items():
                workloads = row.get("workloads") if isinstance(row, dict) else None
                if (not isinstance(workloads, dict) or not {"source", "bytecode"} <= set(workloads)
                        or any(not isinstance(workloads[name], dict)
                               or workloads[name].get("passed") is not True
                               for name in ("source", "bytecode"))):
                    raise harness.HarnessError(f"Lua {name} source or bytecode workload did not pass")
            products["static"] = lua.sha256_file(root / "share/crabc/manifest.json")
        else:
            artifacts: dict[str, dict[str, str]] = {}
            for name, directory in (("installed", "sysroot"), ("extracted", "extracted")):
                row = report.get(name)
                if not isinstance(row, dict) or row.get("passed") is not True:
                    raise harness.HarnessError(f"Lua dynamic {name} source-build lane did not pass")
                admission.validate_pinned_input(row)
                root, _wrapper, _runtime, manifest = dynamic.owned_dynamic_sysroot(state / directory)
                consumer.owned_cleanup.product_snapshot(root, "dynamic")
                environment = row.get("environment")
                workloads = row.get("workloads")
                provenance = json.loads((root / "share/crabc/libc-shared.provenance.json").read_text())
                product_state = json.loads((root / "share/crabc/dynamic-product-state.json").read_text())
                if (provenance.get("allocator_backend") != "native-shadow"
                        or product_state.get("allocator_backend") != "native-shadow"
                        or product_state.get("source_sha256") != source["source_sha256"]
                        or not isinstance(environment, dict)
                        or environment.get("sysroot_manifest") != manifest
                        or not isinstance(workloads, dict)
                        or not {"source", "bytecode"} <= set(workloads)
                        or any(not isinstance(workloads[workload], dict)
                               or workloads[workload].get("passed") is not True
                               for workload in ("source", "bytecode"))):
                    raise harness.HarnessError(f"Lua dynamic {name} report or product changed")
                products[name] = lua.sha256_file(root / "share/crabc/manifest.json")
                artifacts[name] = dynamic.source_artifact_hashes(row)
            reproducibility = report.get("reproducibility")
            if (not isinstance(reproducibility, dict) or reproducibility.get("status") != "passed"
                    or products["installed"] != products["extracted"]
                    or artifacts["installed"] != artifacts["extracted"]
                    or reproducibility.get("installed_artifacts") != artifacts["installed"]
                    or reproducibility.get("extracted_artifacts") != artifacts["extracted"]):
                raise harness.HarnessError("Lua dynamic installed and extracted artifacts differ")
        return {"path": str(report_path), "sha256": lua.sha256_file(report_path),
                "source_identity": source, "products": products}
    except (lua.RunnerError, consumer.owned_cleanup.OwnedCleanupError,
            qualification.QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        raise harness.HarnessError(f"Lua private report is not physically valid: {error}") from error


def run_lua_receipt_reader(lane: str, output: str) -> dict[str, Any]:
    """Check the emitted private report inside the image that owns its root-only state."""

    lines = output.splitlines()
    if len(lines) != 1:
        raise harness.HarnessError("Lua source-build command did not emit one private report summary")
    try:
        summary = json.loads(lines[0])
    except ValueError as error:
        raise harness.HarnessError(f"Lua source-build summary is invalid JSON: {error}") from error
    parent = CONTAINER_ROOT / ".work/x86_64" / f"lua-{lane}-source-build-native-shadow"
    if (not isinstance(summary, dict)
            or set(summary) != {"state_root", "report", "latest_report", "passed"}
            or summary["passed"] is not True or summary["latest_report"] is not None
            or not isinstance(summary["state_root"], str)
            or not isinstance(summary["report"], str)):
        raise harness.HarnessError("Lua source-build summary did not name a private passing report")
    state = Path(summary["state_root"])
    if state.parent != parent or not state.name.startswith("run-") or summary["report"] != str(state / "report.json"):
        raise harness.HarnessError("Lua source-build summary names a foreign report")
    git_directory = Path(qualification.git("rev-parse", "--path-format=absolute", "--git-common-dir").decode().strip())
    command = [
        "docker", "run", "--rm", "--init", "--network", "none", "--platform", "linux/amd64",
        "--volume", f"{harness.ROOT}:{CONTAINER_ROOT}",
        "--volume", f"{git_directory}:{git_directory}:ro", "--workdir", str(CONTAINER_ROOT),
        "--env", "GIT_OPTIONAL_LOCKS=0", "--env", "GIT_CONFIG_COUNT=1",
        "--env", "GIT_CONFIG_KEY_0=safe.directory", "--env", f"GIT_CONFIG_VALUE_0={CONTAINER_ROOT}",
        CORE_IMAGE, "python3", "-B", str(CONTAINER_ROOT / "compat/allocator/x86_64_m8_gate.py"),
        "--read-lua-evidence", lane, summary["report"],
    ]
    result = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
    if result["status"] != 0:
        raise harness.HarnessError("Lua physical receipt reader failed: " + str(result["stderr"])[-1000:])
    try:
        identity = json.loads(str(result["stdout"]))
    except ValueError as error:
        raise harness.HarnessError(f"Lua physical receipt reader returned invalid JSON: {error}") from error
    source = {"revision": qualification.git("rev-parse", "HEAD").decode().strip(),
              "source_sha256": qualification.source_digest()}
    if (not isinstance(identity, dict) or identity.get("path") != summary["report"]
            or identity.get("source_identity") != source
            or not isinstance(identity.get("sha256"), str)
            or not isinstance(identity.get("products"), dict)):
        raise harness.HarnessError("Lua physical receipt identity does not match this checkout")
    return identity


def read_corpus_evidence(report_path: Path, dynamic_sysroot: Path) -> dict[str, Any]:
    """Reread the signed inputs, source, installed runtime, and retained corpus roots."""

    sys.path.insert(0, str(harness.ROOT / "compat/corpus"))
    import run_x86 as corpus

    try:
        report_path = corpus.require_physical_directory(report_path.parent, "corpus run root") / report_path.name
        corpus.sha256_file(report_path, "corpus private report")
        root = report_path.parent
        if (root.parent != corpus.DEFAULT_WORK or not root.name.startswith("owned-package-corpus-")
                or report_path != root / "report.json"):
            raise harness.HarnessError("corpus private report escaped its retained run root")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        manifest = corpus.load_manifest()
        cases = corpus.select_cases(manifest, ("all",))
        product = corpus.validate_product(dynamic_sysroot)
        state = json.loads((dynamic_sysroot / "share/crabc/dynamic-product-state.json").read_text())
        provenance = json.loads((dynamic_sysroot / "share/crabc/libc-shared.provenance.json").read_text())
        source_sha256 = qualification.source_digest()
        if (state.get("allocator_backend") != "native-shadow"
                or state.get("source_sha256") != source_sha256
                or provenance.get("allocator_backend") != "native-shadow"):
            raise harness.HarnessError("corpus product is not current native-shadow source")
        source = corpus.source_identity(manifest)
        inputs = corpus.verify_inputs(manifest, corpus.DEFAULT_INPUT, corpus.DEFAULT_INDEX)
        tools = corpus.apk_identity()
        oracle = corpus.oracle_source_identity()
        if (not isinstance(report, dict) or report.get("schema") != corpus.SCHEMA
                or report.get("source_mount") != str(corpus.ROOT)
                or report.get("execution_root") != str(root)
                or report.get("report_path") != str(report_path)
                or report.get("passed") is not True
                or report.get("source") != {"before": source, "after": source}
                or report.get("inputs") != {"verification_before": inputs, "after": inputs["identity"]}
                or report.get("tools") != {"before": tools, "after": tools}
                or report.get("oracle") != {"before": oracle, "after": oracle}
                or report.get("candidate_product") != {"before": product, "after": product}
                or report.get("case_count") != len(cases)):
            raise harness.HarnessError("corpus report source, input, or product identity changed")
        payload = report.get("application_payload")
        payload_root = root / "application-payload"
        if (not isinstance(payload, dict) or payload.get("path") != str(payload_root)
                or payload.get("package_library_dirs") != list(manifest.package_library_dirs)
                or payload.get("sha256") != corpus.tree_sha256(
                    payload_root, "retained corpus payload", retention_modes=payload.get("retention_modes"))
                or payload.get("elf_closure") != corpus.audit_application_elf_closure(
                    payload_root, manifest.package_library_dirs)):
            raise harness.HarnessError("corpus retained application payload changed")
        outcomes = report.get("outcomes")
        if (not isinstance(outcomes, list) or len(outcomes) != len(cases)
                or [row.get("id") if isinstance(row, dict) else None for row in outcomes]
                != [case.id for case in cases]):
            raise harness.HarnessError("corpus report omits a frozen workload")
        for case, outcome in zip(cases, outcomes):
            if (outcome.get("tier") != case.tier or outcome.get("package") != case.package
                    or outcome.get("path") != case.path or outcome.get("argv") != list(case.argv)
                    or outcome.get("environment") != corpus.CASE_ENVIRONMENT
                    or outcome.get("stateful") is not case.stateful
                    or outcome.get("requires_dt_relr") is not case.requires_dt_relr):
                raise harness.HarnessError(f"corpus workload identity changed: {case.id}")
            roots = outcome.get("roots")
            if not isinstance(roots, dict) or set(roots) != {"oracle", "candidate"}:
                raise harness.HarnessError(f"corpus retained roots are absent: {case.id}")
            for side in ("oracle", "candidate"):
                row = roots[side]
                if not isinstance(row, dict):
                    raise harness.HarnessError(f"corpus retained root is invalid: {case.id} {side}")
                retained = root / f"{case.id}-{side}"
                if row.get("execution_tree_after_sha256") != corpus.tree_sha256(
                        retained, f"{case.id} {side} retained root",
                        retention_modes=row.get("retention_modes")):
                    raise harness.HarnessError(f"corpus retained root changed: {case.id} {side}")
                corpus.assert_runtime_boundary(retained, row["runtime"])
                runtime = row["runtime"]
                expected = product if side == "candidate" else None
                if side == "candidate" and (runtime["loader"]["sha256"] != expected["files"]["lib/ld-crabc-x86_64.so.1"]
                                            or runtime["libc"]["sha256"] != expected["files"]["usr/lib/libc.so"]):
                    raise harness.HarnessError(f"corpus candidate runtime differs from product: {case.id}")
                if side == "oracle" and runtime["libc"]["sha256"] != oracle["runtime"]["sha256"]:
                    raise harness.HarnessError(f"corpus oracle runtime changed: {case.id}")
            comparison = outcome.get("comparison")
            if not isinstance(comparison, dict):
                raise harness.HarnessError(f"corpus comparison is absent: {case.id}")
            compared: dict[str, Any] = {}
            for side in ("oracle", "candidate"):
                result = comparison.get(side)
                if (not isinstance(result, dict) or type(result.get("status")) is not int
                        or type(result.get("timed_out")) is not bool):
                    raise harness.HarnessError(f"corpus result is invalid: {case.id} {side}")
                streams = {}
                for name in ("stdout", "stderr"):
                    snapshot = result.get(name)
                    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("hex"), str):
                        raise harness.HarnessError(f"corpus stream is invalid: {case.id} {side}")
                    data = bytes.fromhex(snapshot["hex"])
                    if corpus.stream_snapshot(data) != snapshot:
                        raise harness.HarnessError(f"corpus stream changed: {case.id} {side}")
                    streams[name] = data
                compared[side] = corpus.ProcessResult(result["status"], streams["stdout"],
                                                      streams["stderr"], result["timed_out"])
            if (comparison != corpus.compare_results(compared["oracle"], compared["candidate"])
                    or comparison.get("passed") is not True):
                raise harness.HarnessError(f"corpus workload did not pass exactly: {case.id}")
        return {"path": str(report_path), "sha256": corpus.sha256_file(report_path, "corpus report"),
                "source_sha256": source_sha256, "product_manifest_sha256": product["manifest_sha256"],
                "input_index_sha256": inputs["identity"]["index"]["sha256"], "case_count": len(cases)}
    except (corpus.CorpusError, qualification.QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        raise harness.HarnessError(f"corpus private report is not physically valid: {error}") from error


def run_corpus_receipt_reader(command: Sequence[str], output: str) -> dict[str, Any]:
    """Bind the command's product and retained report to this checkout."""

    positions = [index for index, value in enumerate(command) if value == "--dynamic-sysroot"]
    if len(positions) != 1 or positions[0] + 1 >= len(command) or "--quiet" not in command:
        raise harness.HarnessError("corpus command did not name one quiet dynamic product")
    product = command[positions[0] + 1]
    if not product.startswith(f"{CONTAINER_ROOT}/.work/"):
        raise harness.HarnessError("corpus dynamic product escaped checkout work")
    prefixes = ("owned package corpus evidence: ", "owned x86_64 package corpus: status: ",
                "owned x86_64 package corpus: report: ")
    found = [[line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
             for prefix in prefixes]
    if any(len(values) != 1 for values in found) or found[1] != ["pass"]:
        raise harness.HarnessError("corpus command did not emit one passing private report")
    root, report_path = Path(found[0][0]), Path(found[2][0])
    if (root.parent != CONTAINER_ROOT / ".work/x86_64/tmp/owned-package-corpus"
            or not root.name.startswith("owned-package-corpus-") or report_path != root / "report.json"):
        raise harness.HarnessError("corpus command named a foreign private report")
    git_directory = Path(qualification.git("rev-parse", "--path-format=absolute", "--git-common-dir").decode().strip())
    reader = [
        "docker", "run", "--rm", "--init", "--network", "none", "--platform", "linux/amd64",
        "--volume", f"{harness.ROOT}:{CONTAINER_ROOT}",
        "--volume", f"{git_directory}:{git_directory}:ro", "--workdir", str(CONTAINER_ROOT),
        "--env", "GIT_OPTIONAL_LOCKS=0", "--env", "GIT_CONFIG_COUNT=1",
        "--env", "GIT_CONFIG_KEY_0=safe.directory", "--env", f"GIT_CONFIG_VALUE_0={CONTAINER_ROOT}",
        CORE_IMAGE, "python3", "-B", str(CONTAINER_ROOT / "compat/allocator/x86_64_m8_gate.py"),
        "--read-corpus-evidence", str(report_path), product,
    ]
    result = harness.command_record(reader, cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
    if result["status"] != 0:
        raise harness.HarnessError("corpus physical receipt reader failed: " + str(result["stderr"])[-1000:])
    try:
        identity = json.loads(str(result["stdout"]))
    except ValueError as error:
        raise harness.HarnessError(f"corpus physical receipt reader returned invalid JSON: {error}") from error
    if (not isinstance(identity, dict) or identity.get("path") != str(report_path)
            or identity.get("source_sha256") != qualification.source_digest()
            or not isinstance(identity.get("sha256"), str)
            or not isinstance(identity.get("product_manifest_sha256"), str)
            or not isinstance(identity.get("input_index_sha256"), str)):
        raise harness.HarnessError("corpus physical receipt identity does not match this checkout")
    return identity


def read_threads_fork_receipt(evidence_id: str, command: Sequence[str], output: str) -> dict[str, Any]:
    """Bind a canonical runner receipt to its executed cases and installed products."""

    runner = "owned-" + evidence_id.removeprefix("product:")
    if evidence_id not in {
            "product:native-worker-lifecycle", "product:native-allocator-fork",
            "product:native-allocator-stress",
    } or command[:2] != [DISPATCHER, runner]:
        raise harness.HarnessError("unexpected native-shadow runner command")
    work_path = product_directory(output, f"{runner.removeprefix('owned-')} evidence: ")
    if work_path is None:
        raise harness.HarnessError(f"{runner} did not emit one private evidence directory")
    try:
        relative = Path(work_path).relative_to(CONTAINER_ROOT / ".work/x86_64/tmp")
        if len(relative.parts) != 1 or not relative.name.startswith(f"{runner}."):
            raise harness.HarnessError(f"{runner} evidence escaped its runner root")
        work = consumer.owned_cleanup.work_child(
            harness.ROOT / ".work/x86_64/tmp" / relative, f"{runner} evidence", existing=True)
        receipt = native_shadow_receipt.read_receipt(harness.ROOT, runner)
        raw = json.loads(receipt.path.read_text(encoding="utf-8"))
        if raw.get("work") != work.relative_to(harness.ROOT).as_posix():
            raise harness.HarnessError(f"{runner} receipt names another execution root")
        if evidence_id == "product:native-allocator-fork":
            if (len(command) != 5 or command[2] != "--static-sysroot"
                    or not command[3].startswith(f"{CONTAINER_ROOT}/.work/")
                    or not command[4].startswith(f"{CONTAINER_ROOT}/.work/")):
                raise harness.HarnessError("fork runner did not consume the supplied native-shadow products")
            roots = [harness.ROOT / Path(value).relative_to(CONTAINER_ROOT)
                     for value in command[3:5]]
        else:
            if len(command) != 2:
                raise harness.HarnessError(f"{runner} used non-canonical arguments")
            roots = [work / "static-sysroot", work / "dynamic-sysroot"]
        static, dynamic = roots
        consumer.owned_cleanup.product_snapshot(static, "static")
        consumer.owned_cleanup.product_snapshot(dynamic, "dynamic")
        special = {
            "probe-source": harness.ROOT / "compat/x86_64" / (
                "owned_native_worker_lifecycle_probe.c" if runner == "owned-native-worker-lifecycle"
                else "owned_native_allocator_fork_probe.c"),
            "c-static-manifest": work / "c-static-sysroot/share/crabc/manifest.json",
            "static-manifest": static / "share/crabc/manifest.json",
            "static-libc-provenance": static / "share/crabc/libc-static.provenance.json",
            "dynamic-manifest": dynamic / "share/crabc/manifest.json",
            "dynamic-libc-provenance": dynamic / "share/crabc/libc-shared.provenance.json",
        }
        required = {"static-manifest", "static-libc-provenance", "dynamic-libc-provenance"}
        if runner == "owned-native-allocator-stress":
            required |= {"c-static-manifest", "stress-oracle", "stress-static-pie",
                         "stress-dynamic-pie", "soak-oracle", "soak-static-pie", "soak-dynamic-pie"}
        else:
            required |= {"probe-source", "dynamic-manifest", "oracle", "static", "static-pie",
                         "dynamic-pie", "dynamic-non-pie"}
        if not required <= set(receipt.products):
            raise harness.HarnessError(f"{runner} receipt omits executed programs or provenance")
        for name, record in receipt.products.items():
            original = consumer.owned_cleanup.physical(special.get(name, work / name),
                                                        f"{runner} product {name}")
            if {"sha256": consumer.owned_cleanup.digest(original), "size": original.stat().st_size} != record:
                raise harness.HarnessError(f"{runner} original product changed: {name}")
        static_manifest = json.loads(special["static-manifest"].read_text(encoding="utf-8"))
        static_provenance = json.loads(special["static-libc-provenance"].read_text(encoding="utf-8"))
        dynamic_provenance = json.loads(special["dynamic-libc-provenance"].read_text(encoding="utf-8"))
        dynamic_state = json.loads((dynamic / "share/crabc/dynamic-product-state.json").read_text())
        if (static_manifest.get("allocator_backend") != "native-shadow"
                or dynamic_provenance.get("allocator_backend") != "native-shadow"
                or dynamic_state.get("allocator_backend") != "native-shadow"
                or dynamic_state.get("source_sha256") != qualification.source_digest()):
            raise harness.HarnessError(f"{runner} product is not current native-shadow source")
        if runner != "owned-native-allocator-fork" and (
                static_provenance.get("allocator_lifecycle_test_audit") is not True
                or dynamic_provenance.get("allocator_lifecycle_test_audit") is not True):
            raise harness.HarnessError(f"{runner} product lacks the lifecycle audit")
        if runner in {"owned-native-worker-lifecycle", "owned-native-allocator-fork"}:
            scenarios = (("main", "final", "deferred") if runner == "owned-native-worker-lifecycle"
                         else ("initial", "worker", "joined", "repeat", "underscore", "synccall-create"))
            expected = [f"oracle-{scenario}" for scenario in scenarios]
            expected += [f"{mode}-{scenario}" for mode in ("static", "static-pie") for scenario in scenarios]
            expected += [f"{entry}-{mode}-{scenario}" for mode in ("pie", "non-pie")
                         for scenario in scenarios for entry in ("kernel", "direct")]
            if receipt.case_ids() != expected:
                raise harness.HarnessError(f"{runner} receipt omits an executed product mode")
        elif (receipt.parameters.get("SKIP") != ""
              or not all(f"stress-32-50-50-{mode}" in receipt.case_ids()
                         for mode in ("oracle", "c-static-pie", "static-pie", "dynamic-pie"))
              or not all(f"soak-{seed}-{mode}" in receipt.case_ids()
                         for seed in ("0x5eed0001", "0x5eed0002", "0x5eed0003")
                         for mode in ("oracle", "c-static-pie", "static-pie", "dynamic-pie"))
              or "soak-growth" not in receipt.case_ids()):
            raise harness.HarnessError("stress receipt omits canonical stress or soak cases")
        return {"path": str(receipt.path), "sha256": consumer.sha256_file(receipt.path),
                "source": dict(receipt.source), "source_sha256": qualification.source_digest(),
                "products": {mode: consumer.sha256_file(root / "share/crabc/manifest.json")
                             for mode, root in (("static", static), ("dynamic", dynamic))},
                "case_count": len(receipt.cases)}
    except (native_shadow_receipt.ReceiptError, consumer.owned_cleanup.OwnedCleanupError,
            qualification.QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        raise harness.HarnessError(f"{runner} physical receipt is invalid: {error}") from error


def read_allocator_override_receipt(command: Sequence[str], output: str) -> dict[str, Any]:
    """Replay application allocator ownership from the retained native-shadow receipt."""

    runner = "owned-allocator-override"
    if (len(command) != 5 or command[:3] != [DISPATCHER, runner, "--static-sysroot"]):
        raise harness.HarnessError("allocator override did not consume two supplied products")
    evidence = product_directory(output, "allocator-override evidence: ")
    if evidence is None:
        raise harness.HarnessError("allocator override did not emit one private evidence directory")
    try:
        work = Path(evidence).relative_to(CONTAINER_ROOT)
        if (work.parent != Path(".work/x86_64/tmp")
                or not work.name.startswith("owned-allocator-override.")):
            raise harness.HarnessError("allocator override evidence escaped its private root")
        roots = []
        for value in command[3:]:
            relative = Path(value).relative_to(CONTAINER_ROOT)
            if not relative.is_relative_to(".work"):
                raise harness.HarnessError("allocator override product escaped checkout work")
            roots.append(harness.ROOT / relative)
        static, dynamic = roots
        receipt = native_shadow_receipt.read_receipt(harness.ROOT, runner, case_prefix="kernel-")
        retained = receipt.path.parent
        raw = json.loads(receipt.path.read_text(encoding="utf-8"))
        if raw.get("work") != work.as_posix() or receipt.parameters != {
                "CASE_TIMEOUT": "30", "SCENARIOS": "full,trio",
                "STATIC_MODES": "static,static-pie",
                "DYNAMIC_MODES": "kernel-pie,direct-pie,kernel-non-pie,direct-non-pie",
                "PROVIDERS": "executable,initial-dso",
        }:
            raise harness.HarnessError("allocator override receipt names another run or workload")
        consumer.owned_cleanup.product_snapshot(static, "static")
        consumer.owned_cleanup.product_snapshot(dynamic, "dynamic")
        scenarios = ("full", "trio")
        dynamic_modes = ("kernel-pie", "direct-pie", "kernel-non-pie", "direct-non-pie")
        expected_cases = []
        expected_products = {
            "static-manifest", "static-libc-provenance", "static-libc-archive",
            "dynamic-manifest", "dynamic-product-state", "dynamic-libc-provenance",
            "dynamic-libc", "dynamic-loader",
        }
        for scenario in scenarios:
            expected_cases += [f"oracle-{scenario}", f"static-{scenario}", f"static-pie-{scenario}"]
            expected_cases += [f"{mode}-{scenario}" for mode in dynamic_modes]
            expected_products.update(f"{name}-{scenario}" for name in (
                "oracle", "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
                "oracle-dso-provider", "oracle-dso-client", "override-dso",
                "dso-client-pie", "dso-client-non-pie"))
        for scenario in scenarios:
            expected_cases += [f"oracle-dso-{scenario}"]
            expected_cases += [f"{mode}-dso-{scenario}" for mode in dynamic_modes]
        expected_cases.append("runner")
        if receipt.case_ids() != expected_cases or set(receipt.products) != expected_products:
            raise harness.HarnessError("allocator override receipt omits a frozen case or ELF product")
        original_products = {
            "static-manifest": static / "share/crabc/manifest.json",
            "static-libc-provenance": static / "share/crabc/libc-static.provenance.json",
            "static-libc-archive": static / "usr/lib/libc.a",
            "dynamic-manifest": dynamic / "share/crabc/manifest.json",
            "dynamic-product-state": dynamic / "share/crabc/dynamic-product-state.json",
            "dynamic-libc-provenance": dynamic / "share/crabc/libc-shared.provenance.json",
            "dynamic-libc": dynamic / "usr/lib/libc.so",
            "dynamic-loader": dynamic / "lib/ld-crabc-x86_64.so.1",
        }
        for name, original in original_products.items():
            original = consumer.owned_cleanup.physical(original, f"allocator override {name}")
            if {"sha256": consumer.owned_cleanup.digest(original), "size": original.stat().st_size} != receipt.products[name]:
                raise harness.HarnessError(f"allocator override used another supplied product: {name}")
        static_manifest = json.loads((retained / "products/static-manifest").read_text())
        dynamic_provenance = json.loads((retained / "products/dynamic-libc-provenance").read_text())
        dynamic_state = json.loads((retained / "products/dynamic-product-state").read_text())
        if (static_manifest.get("allocator_backend") != "native-shadow"
                or dynamic_provenance.get("allocator_backend") != "native-shadow"
                or dynamic_state.get("allocator_backend") != "native-shadow"
                or dynamic_state.get("source_sha256") != qualification.source_digest()):
            raise harness.HarnessError("allocator override product is not current native-shadow source")

        def symbols(name: str) -> dict[str, set[str]]:
            path = retained / "products" / name
            result = subprocess.run(["readelf", "-Ws", str(path)], capture_output=True, text=True, check=False)
            if result.returncode:
                raise harness.HarnessError(f"allocator override ELF symbols are unreadable: {name}")
            definitions: dict[str, set[str]] = {}
            for line in result.stdout.splitlines():
                fields = line.split()
                if (len(fields) >= 8 and fields[0].endswith(":") and fields[3] == "FUNC"
                        and fields[4] == "GLOBAL" and fields[6] != "UND"):
                    definitions.setdefault(fields[7].split("@")[0], set()).add(fields[6])
            return definitions

        trio = {"malloc", "free", "realloc"}
        full = trio | {"calloc", "aligned_alloc", "posix_memalign", "memalign", "malloc_usable_size"}
        for scenario in scenarios:
            required_symbols = full if scenario == "full" else trio
            for name in (f"static-{scenario}", f"static-pie-{scenario}",
                         f"dynamic-pie-{scenario}", f"dynamic-non-pie-{scenario}",
                         f"override-dso-{scenario}"):
                if not required_symbols <= set(symbols(name)):
                    raise harness.HarnessError(f"allocator override ELF lacks strong application entries: {name}")
            for name in (f"dso-client-pie-{scenario}", f"dso-client-non-pie-{scenario}"):
                if trio & set(symbols(name)):
                    raise harness.HarnessError(f"allocator override DSO client defines the provider's entries: {name}")
                dynamic_tags = subprocess.run(["readelf", "-dW", str(retained / "products" / name)],
                                              capture_output=True, text=True, check=False)
                if dynamic_tags.returncode or f"[liboverride-{scenario}.so]" not in dynamic_tags.stdout:
                    raise harness.HarnessError(f"allocator override DSO client lacks its initial provider: {name}")

        logs = retained / "logs"
        for case in expected_cases:
            if (logs / f"{case}.status").read_bytes() != b"0\n":
                raise harness.HarnessError(f"allocator override retained status changed: {case}")
            if case == "runner":
                continue
            if (logs / f"{case}.stderr").read_bytes():
                raise harness.HarnessError(f"allocator override retained stderr is nonempty: {case}")
        for scenario in scenarios:
            for oracle, cases in (
                    (f"oracle-{scenario}", [f"static-{scenario}", f"static-pie-{scenario}",
                                           *(f"{mode}-{scenario}" for mode in dynamic_modes)]),
                    (f"oracle-dso-{scenario}", [f"{mode}-dso-{scenario}" for mode in dynamic_modes])):
                transcript = (logs / f"{oracle}.stdout").read_bytes()
                if not transcript or any((logs / f"{case}.stdout").read_bytes() != transcript for case in cases):
                    raise harness.HarnessError(f"allocator override transcript differs from pinned musl: {scenario}")
        return {"path": str(receipt.path), "sha256": consumer.sha256_file(receipt.path),
                "source": dict(receipt.source), "source_sha256": qualification.source_digest(),
                "products": {mode: consumer.sha256_file(root / "share/crabc/manifest.json")
                             for mode, root in (("static", static), ("dynamic", dynamic))},
                "case_count": len(receipt.cases)}
    except (native_shadow_receipt.ReceiptError, consumer.owned_cleanup.OwnedCleanupError,
            qualification.QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        raise harness.HarnessError(f"allocator override physical receipt is invalid: {error}") from error


def read_startup_constructor_receipt(command: Sequence[str], output: str) -> dict[str, Any]:
    """Bind the executed startup and errno matrix to the supplied native-shadow sysroots."""

    if (len(command) != 5 or command[:3] != [
            DISPATCHER, startup_errno.RUNNER, "--static-sysroot",
    ]):
        raise harness.HarnessError("startup errno runner did not consume two supplied products")
    evidence = product_directory(output, "owned mimalloc startup errno evidence: ")
    if evidence is None:
        raise harness.HarnessError("startup errno runner did not emit one private evidence directory")
    try:
        work = Path(evidence).relative_to(CONTAINER_ROOT)
        if (work.parent != Path(".work/x86_64/tmp")
                or not work.name.startswith("owned-mimalloc-startup-errno.")):
            raise harness.HarnessError("startup errno evidence escaped its private root")
        roots = []
        for value in command[3:]:
            relative = Path(value).relative_to(CONTAINER_ROOT)
            if not relative.is_relative_to(".work"):
                raise harness.HarnessError("startup errno product escaped checkout work")
            roots.append(harness.ROOT / relative)
        static, dynamic = roots
        receipt = startup_errno.read_startup_errno_receipt(harness.ROOT)
        raw = json.loads(receipt.path.read_text(encoding="utf-8"))
        if raw.get("work") != work.as_posix():
            raise harness.HarnessError("startup errno receipt names another execution root")
        consumer.owned_cleanup.product_snapshot(static, "static")
        consumer.owned_cleanup.product_snapshot(dynamic, "dynamic")
        sources = {
            "input-startup-source": harness.ROOT / "compat/x86_64/owned_mimalloc_startup_errno_probe.c",
            "input-success-source": harness.ROOT / "compat/x86_64/owned_success_errno_probe.c",
            "input-static-manifest": static / "share/crabc/manifest.json",
            "input-static-libc-provenance": static / "share/crabc/libc-static.provenance.json",
            "input-static-libc": static / "usr/lib/libc.a",
            "input-dynamic-manifest": dynamic / "share/crabc/manifest.json",
            "input-dynamic-libc-provenance": dynamic / "share/crabc/libc-shared.provenance.json",
            "input-dynamic-loader-provenance": dynamic / "share/crabc/loader.provenance.json",
            "input-dynamic-libc": dynamic / "usr/lib/libc.so",
            "input-dynamic-loader": dynamic / "lib/ld-crabc-x86_64.so.1",
        }
        for name, original in sources.items():
            original = consumer.owned_cleanup.physical(original, f"startup errno {name}")
            if {"sha256": consumer.owned_cleanup.digest(original), "size": original.stat().st_size} != receipt.products[name]:
                raise harness.HarnessError(f"startup errno receipt used another input product: {name}")
        state = json.loads((dynamic / "share/crabc/dynamic-product-state.json").read_text())
        if (state.get("allocator_backend") != "native-shadow"
                or state.get("source_sha256") != qualification.source_digest()):
            raise harness.HarnessError("startup errno product is not current native-shadow source")
        return {"path": str(receipt.path), "sha256": consumer.sha256_file(receipt.path),
                "source": dict(receipt.source), "source_sha256": qualification.source_digest(),
                "products": {mode: consumer.sha256_file(root / "share/crabc/manifest.json")
                             for mode, root in (("static", static), ("dynamic", dynamic))},
                "case_count": len(receipt.cases)}
    except (native_shadow_receipt.ReceiptError, consumer.owned_cleanup.OwnedCleanupError,
            qualification.QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        raise harness.HarnessError(f"startup errno physical receipt is invalid: {error}") from error


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
        if evidence_id == "product:native-allocator-policy" and passed:
            try:
                receipt = read_native_allocator_policy_receipt(
                    command, str(record["stdout"]) + str(record["stderr"]))
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"native allocator policy receipt reader: {error}\n")
                passed = False
                directory = None
        if evidence_id == "consumer:rust-std-lto" and passed:
            try:
                receipt = read_native_shadow_receipt(command, qualification.source_digest())
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"M8 receipt reader: {error}\n")
                passed = False
        if evidence_id in {"consumer:lua-static", "consumer:lua-dynamic"} and passed:
            try:
                receipt = run_lua_receipt_reader(
                    evidence_id.removeprefix("consumer:lua-"), str(record["stdout"]))
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"M8 Lua receipt reader: {error}\n")
                passed = False
        if evidence_id == "product:package-corpus" and passed:
            try:
                receipt = run_corpus_receipt_reader(command, str(record["stdout"]) + str(record["stderr"]))
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"M8 corpus receipt reader: {error}\n")
                passed = False
        if evidence_id in {"product:native-worker-lifecycle", "product:native-allocator-fork",
                           "product:native-allocator-stress"} and passed:
            try:
                receipt = read_threads_fork_receipt(
                    evidence_id, command, str(record["stdout"]) + str(record["stderr"]))
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"native-shadow runner receipt reader: {error}\n")
                passed = False
        if evidence_id == "product:allocator-override" and passed:
            try:
                receipt = read_allocator_override_receipt(
                    command, str(record["stdout"]) + str(record["stderr"]))
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"allocator override receipt reader: {error}\n")
                passed = False
        if evidence_id == "product:mimalloc-startup-errno" and passed:
            try:
                receipt = read_startup_constructor_receipt(
                    command, str(record["stdout"]) + str(record["stderr"]))
            except harness.HarnessError as error:
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(f"startup errno receipt reader: {error}\n")
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
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) == 3 and argv[0] == "--read-lua-evidence":
        print(json.dumps(read_lua_evidence(argv[1], Path(argv[2])), sort_keys=True))
        return 0
    if len(argv) == 3 and argv[0] == "--read-corpus-evidence":
        print(json.dumps(read_corpus_evidence(Path(argv[1]), Path(argv[2])), sort_keys=True))
        return 0
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
