#!/usr/bin/env python3
"""Replay the selected private x86 loader runtime-function resolution boundary.

This is a finite, supplied-product reader.  It does not build a sysroot, turn
private protocol imports into libc exports, or replace the existing fork and
timer workload readers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import native_abi_elf_facts as elf_facts
import owned_dynamic_fork_evidence as fork_evidence
import owned_dynamic_receipt as dynamic_receipt
import owned_posix_product_evidence as product_evidence
import owned_posix_timers_evidence as timer_evidence

ROOT = inventory.ROOT
CONTRACT_PATH = ROOT / "compat/x86_64/loader-runtime-registry-private-resolution.toml"
SCHEMA = "crabc.x86_64-loader-runtime-registry-private-resolution/v1"
TARGET = "x86_64-unknown-linux-musl"
FEATURE = "x86_64-owned-dynamic-runtime"
RAW = "raw"

SOURCE_FILES = (
    "compat/x86_64/loader_runtime_registry_evidence.py",
    "compat/x86_64/loader-runtime-registry-private-resolution.toml",
    "compat/x86_64/run_general_dynamic_dlopen.sh",
    "compat/x86_64/run_general_dynamic_fork.sh",
    "compat/x86_64/run_owned_posix_timers.sh",
    "compat/x86_64/owned_dynamic_fork_evidence.py",
    "compat/x86_64/owned_posix_timers_evidence.py",
    "compat/x86_64/general_dynamic_tls_consumer.c",
    "ldso/Cargo.toml",
    "ldso/src/x86_64_runtime_registry.rs",
    "ldso/src/x86_64_initial_worker_tls.rs",
    "ldso/src/x86_64_general_relocation.rs",
    "libc/src/c_abi/x86_64/general_dlfcn.rs",
    "libc/src/c_abi/x86_64/dynamic_tls.rs",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
    "scripts/build_x86_64_owned_dynamic_sysroot.py",
)

# This is deliberately a name map rather than a prefix or a search for all
# loader symbols.  It is the complete protocol selected by the contract.
RESOLVERS = {
    "__crabc_x86_64_reset_current_tls_v1": "reset_current_tls",
    "__crabc_x86_64_runtime_open": "runtime_open",
    "__crabc_x86_64_runtime_symbol": "runtime_symbol",
    "__crabc_x86_64_runtime_close": "runtime_close",
    "__crabc_x86_64_runtime_address": "runtime_address_info",
    "__crabc_x86_64_runtime_fork_prepare": "runtime_fork_prepare",
    "__crabc_x86_64_runtime_fork_complete": "runtime_fork_complete",
    "__crabc_x86_64_runtime_information": "runtime_information",
    "__crabc_x86_64_runtime_iterate": "runtime_iterate",
}
DLFCN_NAMES = tuple(name for name, _ in RESOLVERS.items() if "runtime_" in name and "fork" not in name)
FORK_NAMES = ("__crabc_x86_64_runtime_fork_prepare", "__crabc_x86_64_runtime_fork_complete")
RESET_NAME = "__crabc_x86_64_reset_current_tls_v1"
DLOPEN_MODES = ("pie", "non-pie")
DLOPEN_DRIVER_MODES = {"pie": "pie", "non-pie": "exec"}
TIMER_MODES = ("pie", "non-pie")
EXPECTED_GROWTH = b"runtime TLS: old/new workers, 41 modules, retained addresses, recursive/concurrent constructors\n"
EXPECTED_DLOPEN = b"nested-dlopen=42\n"
EXPECTED_TBSS = b"initial-tbss=8192,worker=isolated\n"
# The retained runners invoke the image's existing `chroot` command and the
# timer reset source test invokes the pinned image's `rustc` wrapper.  Keep
# those exact locations available while excluding inherited host
# configuration, then seal this exact environment in every outer transcript.
WORKLOAD_ENVIRONMENT = {"PATH": "/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
DLFCN_SKIP_SEARCH_ENV = "CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH"


class RuntimeRegistryEvidenceError(RuntimeError):
    """A supplied product, source or retained runtime observation drifted."""


def fail(message: str) -> None:
    raise RuntimeRegistryEvidenceError(f"loader runtime registry evidence: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def same(left: object, right: object) -> bool:
    """JSON comparison where booleans and integers are never interchangeable."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def physical_directory(path: Path, description: str) -> Path:
    try:
        return inventory.physical_directory(path, description)
    except inventory.InventoryError as error:
        raise RuntimeRegistryEvidenceError(str(error)) from error


def physical_regular(path: Path, description: str) -> Path:
    try:
        return inventory.physical_regular(path, description)
    except inventory.InventoryError as error:
        raise RuntimeRegistryEvidenceError(str(error)) from error


def identity(path: Path, *, logical_path: str | None = None) -> dict[str, object]:
    try:
        return inventory.file_record(path, logical_path=logical_path)
    except inventory.InventoryError as error:
        raise RuntimeRegistryEvidenceError(str(error)) from error


def read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        return inventory.read_json(path, description)
    except inventory.InventoryError as error:
        raise RuntimeRegistryEvidenceError(str(error)) from error


def exact(value: object, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{description} fields drifted")
    return value


def source_file(root: Path, relative: str) -> Path:
    path = physical_regular(root / relative, f"source {relative}")
    try:
        require(path.is_relative_to(root), f"source {relative} escapes checkout")
    except ValueError:
        fail(f"source {relative} escapes checkout")
    return path


def source_records(root: Path) -> dict[str, dict[str, object]]:
    return {relative: identity(source_file(root, relative), logical_path=relative) for relative in SOURCE_FILES}


def validate_source_records(root: Path, records: object) -> None:
    record = exact(records, set(SOURCE_FILES), "component source roster")
    expected = source_records(root)
    require(same(record, expected), "component source bytes changed")


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    try:
        record = tomllib.loads(source_file(root, CONTRACT_PATH.relative_to(ROOT).as_posix()).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RuntimeRegistryEvidenceError("runtime registry contract is unreadable") from error
    validate_contract(record)
    return record


def validate_contract(contract: object) -> None:
    record = exact(contract, {"schema", "id", "status", "target", "operation", "relocation", "limits"}, "runtime registry contract")
    require((record["schema"], record["id"], record["status"], record["target"]) == (
        "crabc.x86_64-loader-runtime-registry-private-resolution-contract/v1",
        "x86-loader-runtime-registry-private-resolution", "implemented-unqualified", TARGET),
        "runtime registry contract identity drifted")
    operations = record["operation"]
    require(type(operations) is list and len(operations) == len(RESOLVERS), "runtime registry operation roster drifted")
    seen: dict[str, str] = {}
    expected_consumers = {**{name: ("general_dlfcn", "runtime-tls-41-modules") for name in DLFCN_NAMES},
                          **{name: ("dynamic_fork", "all-100-fork-cells") for name in FORK_NAMES},
                          RESET_NAME: ("timer_reset", "dynamic-pie-and-non-pie-kernel-and-direct")}
    for operation in operations:
        row = exact(operation, {"name", "resolver", "consumer", "scenario"}, "runtime registry operation")
        name, resolver = row["name"], row["resolver"]
        require(type(name) is str and type(resolver) is str and type(row["consumer"]) is str and type(row["scenario"]) is str,
                "runtime registry operation values drifted")
        require(name not in seen, "runtime registry operation is duplicated")
        seen[name] = resolver
        require(expected_consumers.get(name) == (row["consumer"], row["scenario"]), "runtime registry operation scenario drifted")
    require(seen == RESOLVERS, "runtime registry resolver roster drifted")
    relocation = exact(record["relocation"], {"feature", "kinds", "symbol", "addend"}, "runtime registry relocation")
    require(relocation == {"feature": FEATURE, "kinds": ["R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"],
                           "symbol": "GLOBAL DEFAULT UND NOTYPE", "addend": 0},
            "runtime registry relocation contract drifted")
    limits = exact(record["limits"], {"public_provider", "runtime_v1_worker_protocol", "crt_structural_leaves",
                                       "family_completion", "promotion_ready"}, "runtime registry limits")
    require(all(value is False for value in limits.values()), "runtime registry nonpromotion limits drifted")


def source_resolution(root: Path = ROOT) -> dict[str, object]:
    """Authenticate the exact closed resolver and its selected build gate."""
    registry = source_file(root, "ldso/src/x86_64_runtime_registry.rs").read_text(encoding="utf-8")
    matches = re.findall(r'\bb"([^"]+)"\s*=>\s*Some\((\w+)\s+as \*const \(\)', registry)
    found = {"__" + name if not name.startswith("__") else name: resolver for name, resolver in matches}
    require(found == RESOLVERS, "runtime_function is not the exact closed nine-name resolver")
    # Initial worker routing must delegate unknown protocol names to that
    # closed table; it cannot widen a three-name worker table into this owner.
    worker = source_file(root, "ldso/src/x86_64_initial_worker_tls.rs").read_text(encoding="utf-8")
    require("_ => x86_64_runtime_registry::runtime_function(name)" in worker,
            "initial worker runtime resolver does not delegate to the registry")
    relocation = source_file(root, "ldso/src/x86_64_general_relocation.rs").read_text(encoding="utf-8")
    for fragment in (
        '#[cfg(feature = "x86_64-owned-dynamic-runtime")]',
        "x86_64_initial_worker_tls::runtime_function",
        "matches!(kind, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT)",
        "addend == 0", "requested.section == 0", "requested.binding == 1",
        "requested.visibility == 0", "matches!(requested.kind, 0 | 2)",
    ):
        require(fragment in relocation, f"runtime relocation gate omits {fragment!r}")
    dynamic_tls = source_file(root, "libc/src/c_abi/x86_64/dynamic_tls.rs").read_text(encoding="utf-8")
    dlfcn = source_file(root, "libc/src/c_abi/x86_64/general_dlfcn.rs").read_text(encoding="utf-8")
    for name in DLFCN_NAMES:
        require(f"fn {name}(" in dlfcn, f"dlfcn consumer omits {name}")
    for name in (*FORK_NAMES, RESET_NAME):
        require(f"fn {name}(" in dynamic_tls, f"dynamic TLS consumer omits {name}")
    static_root = source_file(root, "libc/src/c_abi/x86_64/static_c_abi.rs").read_text(encoding="utf-8")
    require('#[cfg_attr(feature = "x86-owned-dynamic-runtime", path = "dynamic_tls.rs")]' in static_root,
            "selected libc root does not select dynamic TLS consumer")
    cargo = source_file(root, "ldso/Cargo.toml").read_text(encoding="utf-8")
    require('x86_64-owned-dynamic-runtime = ["x86_64-general-initial-lifecycle", "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter"]' in cargo,
            "loader selected feature closure drifted")
    return {"resolvers": dict(sorted(RESOLVERS.items())), "feature": FEATURE}


def _symbol_rows(facts: Mapping[str, Any], artifact: str) -> list[Mapping[str, Any]]:
    try:
        tables = facts["facts"][artifact]["symbol_tables"]
    except (KeyError, TypeError) as error:
        raise RuntimeRegistryEvidenceError(f"complete ELF facts omit {artifact} tables") from error
    require(type(tables) is list, f"complete ELF facts {artifact} tables drifted")
    selected: list[Mapping[str, Any]] = []
    for table in tables:
        if not isinstance(table, dict) or table.get("name") not in {".dynsym", ".symtab"}:
            continue
        rows = table.get("rows")
        require(type(rows) is list, f"complete ELF facts {artifact} row table drifted")
        selected.extend(row for row in rows if isinstance(row, dict) and row.get("name") in RESOLVERS)
    return selected


def import_placement(facts: Mapping[str, Any]) -> dict[str, dict[str, object]]:
    """Require exactly the nine genuine shared-libc undefined protocol imports."""
    artifacts = facts.get("artifacts")
    require(type(artifacts) is dict and set(("candidate-shared", "candidate-loader")) <= set(artifacts),
            "complete ELF facts omit candidate shared/loader placements")
    shared_rows = _symbol_rows(facts, "candidate-shared")
    loader_rows = _symbol_rows(facts, "candidate-loader")
    result: dict[str, dict[str, object]] = {}
    for name in RESOLVERS:
        selected = [row for row in shared_rows if row.get("name") == name]
        require(len(selected) == 2, f"shared libc protocol import {name} is not present once in dynsym and symtab")
        for row in selected:
            require(row.get("type") == "NOTYPE" and row.get("binding") == "GLOBAL" and row.get("visibility") == "DEFAULT"
                    and row.get("section_index") == "UND" and row.get("version") is None
                    and row.get("version_default") is False and row.get("size_bytes") == 0 and row.get("value") == "0000000000000000",
                    f"shared libc protocol import {name} metadata drifted")
        require(not any(row.get("name") == name for row in loader_rows),
                f"candidate loader unexpectedly exports or imports protocol name {name}")
        dynsym = next(row for row in selected if row.get("raw_name") == name and row.get("row_index") is not None)
        result[name] = {key: dynsym[key] for key in ("type", "binding", "visibility", "section_index", "size_bytes", "value", "version", "version_default")}
    return result


def _sha_current(root: Path, relative: str) -> str:
    return hashlib.sha256(source_file(root, relative).read_bytes()).hexdigest()


def loader_provenance(root: Path, dynamic_product: Path, facts: Mapping[str, Any]) -> dict[str, object]:
    """Join the selected feature's own provenance to the exact loader bytes."""
    dynamic_product = physical_directory(dynamic_product, "dynamic product")
    provenance_path = dynamic_product / "share/crabc/loader.provenance.json"
    provenance = read_json(provenance_path, "loader provenance")
    require(provenance.get("schema") == "crabc.x86_64-owned-loader-provenance/v1" and provenance.get("target") == TARGET,
            "loader provenance identity drifted")
    loader = identity(dynamic_product / "lib/ld-crabc-x86_64.so.1", logical_path="lib/ld-crabc-x86_64.so.1")
    fact_loader = facts["artifacts"]["candidate-loader"]["identity"]
    require(same(loader, {**fact_loader, "path": "lib/ld-crabc-x86_64.so.1"}), "complete ELF loader placement differs from supplied dynamic product")
    artifact = exact(provenance.get("artifact"), {"path", "sha256", "mode"}, "loader provenance artifact")
    require(artifact == {key: loader[key] for key in ("path", "sha256", "mode")}, "loader provenance artifact differs from supplied loader")
    cargo = exact(provenance.get("cargo"), {"argv", "rustflags"}, "loader provenance cargo")
    argv = cargo["argv"]
    require(type(argv) is list and all(type(item) is str for item in argv) and argv.count("--no-default-features") == 1,
            "loader provenance default-feature selection drifted")
    positions = [index for index, value in enumerate(argv) if value == "--features"]
    require(len(positions) == 1 and positions[0] + 1 < len(argv) and argv[positions[0] + 1] == FEATURE,
            "loader provenance feature selection drifted")
    require(type(cargo["rustflags"]) is str and "-C relocation-model=pic" in cargo["rustflags"],
            "loader provenance Rust flags drifted")
    required = {
        "ldso/src/x86_64_runtime_registry.rs", "ldso/src/x86_64_initial_worker_tls.rs",
        "ldso/src/x86_64_general_relocation.rs", "ldso/Cargo.toml",
        "scripts/build_x86_64_owned_dynamic_sysroot.py",
    }
    records: dict[str, Mapping[str, Any]] = {}
    for group in ("compiler_dependencies", "configuration"):
        values = provenance.get(group)
        require(type(values) is list, f"loader provenance {group} drifted")
        for row in values:
            row = exact(row, {"path", "sha256", "mode"}, f"loader provenance {group} row")
            path = row["path"]
            require(type(path) is str and type(row["sha256"]) is str and type(row["mode"]) is int,
                    f"loader provenance {group} row types drifted")
            require(path not in records, "loader provenance source path is duplicated")
            records[path] = row
    require(required <= set(records), "loader provenance omits registry source or selected builder")
    for relative in required:
        record = records[relative]
        require(record["sha256"] == _sha_current(root, relative), f"loader provenance source {relative} is stale")
        require(record["mode"] == stat.S_IMODE(source_file(root, relative).stat().st_mode),
                f"loader provenance source mode {relative} drifted")
    return {"loader": loader, "feature": FEATURE,
            "provenance": identity(provenance_path, logical_path="share/crabc/loader.provenance.json")}


def validate_supplied_products(*, root: Path, base_inventory: Path, elf_report: Path,
                               static_preparation: Path, static_product: Path,
                               dynamic_product: Path) -> dict[str, object]:
    """Authenticate the same supplied cohort without building or selecting ABI."""
    root = Path(root).absolute()
    contract = load_contract(root)
    source = source_resolution(root)
    try:
        facts = elf_facts.validate_report(Path(elf_report), base_inventory=Path(base_inventory),
                                          static_product=Path(static_product), dynamic_product=Path(dynamic_product),
                                          static_preparation=Path(static_preparation))
    except (inventory.InventoryError, OSError, ValueError) as error:
        raise RuntimeRegistryEvidenceError("supplied complete ELF facts are not current and valid") from error
    imports = import_placement(facts)
    provenance = loader_provenance(root, Path(dynamic_product), facts)
    return {"contract": {"id": contract["id"], "status": contract["status"]},
            "source": inventory.collector_source_seal(), "source_resolution": source,
            "source_files": source_records(root), "elf_report": identity(Path(elf_report)),
            "imports": imports, "loader": provenance,
            "products": {"static": identity(Path(static_product) / "usr/lib/libc.a"),
                         "dynamic_libc": identity(Path(dynamic_product) / "usr/lib/libc.so"),
                         "dynamic_loader": identity(Path(dynamic_product) / "lib/ld-crabc-x86_64.so.1")}}


def _raw_record(output: Path, path: Path, logical: str) -> dict[str, object]:
    return identity(path, logical_path=logical)


def _read_stream(output: Path, record: object, logical: str) -> bytes:
    row = exact(record, {"path", "sha256", "size", "mode"}, logical)
    require(row["path"] == logical, f"{logical} path drifted")
    path = physical_regular(output / logical, logical)
    require(same(row, identity(path, logical_path=logical)), f"{logical} bytes drifted")
    return path.read_bytes()


def _link_record(product: Path, work: Path, output: Path, stem: str, mode: str) -> dict[str, object]:
    executable = physical_regular(work / stem, f"{stem} executable")
    receipt_path = physical_regular(work / f"{stem}.crabc-link.json", f"{stem} owned driver receipt")
    receipt = read_json(receipt_path, f"{stem} owned driver receipt")
    try:
        dynamic_receipt.validate(receipt, format=product_evidence.DYNAMIC_PRODUCT_FORMAT,
                                 label=stem, fail=fail, allow_application_dso_closure=True)
    except (RuntimeRegistryEvidenceError, KeyError, TypeError, ValueError):
        raise
    require(receipt.get("mode") == mode and receipt.get("output_sha256") == hashlib.sha256(executable.read_bytes()).hexdigest(),
            f"{stem} owned driver receipt does not bind the executable")
    manifest = identity(product / "share/crabc/manifest.json")
    require(receipt.get("manifest_sha256") == manifest["sha256"], f"{stem} owned driver receipt uses another product")
    # The generic receipt schema establishes search and closure semantics.  At
    # this workload boundary also reopen each concrete retained application
    # DSO and each owned runtime input, so an intact sidecar cannot describe a
    # different product or a substituted DSO next to the executable.
    applications = receipt.get("application_dsos")
    require(type(applications) is dict and all(type(name) is str and type(digest) is str
                                               for name, digest in applications.items()),
            f"{stem} application DSO receipt drifted")
    for name, expected_hash in applications.items():
        application = physical_regular(work / name, f"{stem} application DSO {name}")
        require(hashlib.sha256(application.read_bytes()).hexdigest() == expected_hash,
                f"{stem} application DSO {name} differs from its receipt")
    owned = receipt.get("owned_runtime_inputs")
    inputs = receipt.get("input_receipts")
    require(type(owned) is list and type(inputs) is list and all(type(name) is str for name in owned),
            f"{stem} owned runtime input receipt drifted")
    for relative in owned:
        supplied = physical_regular(product / relative, f"{stem} supplied runtime input {relative}")
        matches = [item for item in inputs if isinstance(item, dict)
                   and Path(str(item.get("path", ""))).as_posix().endswith("/" + relative)
                   and item.get("sha256") == hashlib.sha256(supplied.read_bytes()).hexdigest()]
        require(len(matches) == 1, f"{stem} supplied runtime input {relative} is not bound by its receipt")
    return {"executable": identity(executable, logical_path=(work / stem).relative_to(output).as_posix()),
            "receipt": identity(receipt_path, logical_path=(work / f"{stem}.crabc-link.json").relative_to(output).as_posix()),
            "mode": mode}


def validate_growth_output(candidate: bytes, oracle: bytes) -> None:
    """Preserve the 41-module assertion and the existing whole-stream oracle check."""
    require(candidate.startswith(EXPECTED_GROWTH), "general dlfcn 41-module output drifted")
    require(candidate == oracle, "general dlfcn 41-module differential drifted")


def single_driver_mode(modes: set[object]) -> str:
    """Return one receipt mode from the driver's own closed spelling."""
    require(len(modes) == 1 and modes <= set(DLOPEN_DRIVER_MODES.values()),
            "general dlfcn executable mode roster drifted")
    mode = next(iter(modes))
    assert isinstance(mode, str)
    return mode


def dlfcn_observations(product: Path, output: Path, work: Path) -> dict[str, object]:
    """Read the existing 41-module workload without treating its PASS as proof."""
    product = physical_directory(product, "dynamic product")
    output = physical_directory(output, "component evidence output")
    work = physical_directory(work, "general dlfcn work")
    require(work.is_relative_to(output), "general dlfcn work escapes retained component output")
    output_by_mode: dict[str, object] = {}
    expected = ("libnested_leaf.so", "libnested_mid.so", "consumer", "tbss-consumer", "growth",
                "libfailure.so", "libfailure-ie.so", "failure", "libscope-first.so", "libscope-second.so", "scope")
    for name in expected:
        physical_regular(work / name, f"general dlfcn {name}")
    for generation in range(41):
        physical_regular(work / f"libgrowth{generation}.so", "general dlfcn growth DSO")
    require((work / "consumer.stdout").read_bytes() == EXPECTED_DLOPEN, "general dlfcn nested runtime output drifted")
    require((work / "tbss-candidate.stdout").read_bytes() == EXPECTED_TBSS, "general dlfcn TBSS output drifted")
    validate_growth_output((work / "growth.stdout").read_bytes(), (work / "oracle.stdout").read_bytes())
    dso_links: dict[str, object] = {}
    for stem in (*expected, *(f"libgrowth{generation}.so" for generation in range(41))):
        # The driver chooses `shared` for DSOs; executables are recorded below.
        if stem.endswith(".so"):
            dso_links[stem] = _link_record(product, work, output, stem, "shared")
    # The caller records one actual selected entry mode.  Infer it from the
    # executable receipts only after every DSO receipt has been bound.
    # `crabc-cc-dynamic` stores `pie`/`non-pie` as its receipt mode only if the
    # current driver does; derive exact one mode from every executable rather
    # than relying on a runner label.
    modes = {read_json(work / f"{stem}.crabc-link.json", f"{stem} receipt").get("mode")
             for stem in ("consumer", "tbss-consumer", "growth", "failure", "scope")}
    mode = single_driver_mode(modes)
    # Reread with the actual mode (the first lookup above catches wrong shape
    # and keeps only a bounded artifact path surface).
    entries = {key: _link_record(product, work, output, stem, mode) for key, stem in
               {"consumer": "consumer", "tbss": "tbss-consumer", "growth": "growth", "failure": "failure", "scope": "scope"}.items()}
    streams = {}
    for name in ("consumer.stdout", "tbss-candidate.stdout", "tbss-oracle.stdout", "growth.stdout", "oracle.stdout",
                 "scope.stdout", "oracle-scope.stdout", *(f"failure-{case}.stdout" for case in ("ie", "unresolved", "array-half", "tls-filesz", "relocation-kind"))):
        path = physical_regular(work / name, f"general dlfcn raw {name}")
        streams[name] = identity(path, logical_path=(work / name).relative_to(output).as_posix())
    return {"driver_mode": mode, "work": str(work.relative_to(output)), "dso_links": dso_links, "links": entries, "streams": streams,
            "growth_modules": 41, "operations": list(DLFCN_NAMES), "scenario": "runtime-tls-41-modules"}


def _capture(command: list[str], *, output: Path, label: str, environment: Mapping[str, str]) -> dict[str, object]:
    raw = output / RAW
    raw.mkdir(exist_ok=True)
    stdout, stderr, status = (raw / f"{label}.stdout", raw / f"{label}.stderr", raw / f"{label}.status")
    with stdout.open("xb") as out, stderr.open("xb") as err:
        result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                env=dict(environment), check=False)
    status.write_text(f"{result.returncode}\n", encoding="ascii")
    require(result.returncode == 0, f"{label} command failed ({result.returncode})")
    return {"argv": command, "environment": dict(environment), "stdout": _raw_record(output, stdout, f"raw/{label}.stdout"),
            "stderr": _raw_record(output, stderr, f"raw/{label}.stderr"),
            "status": _raw_record(output, status, f"raw/{label}.status")}


def _new_work(parent: Path, prefix: str, before: set[Path]) -> Path:
    after = set(parent.glob(prefix + ".*"))
    created = after - before
    require(len(created) == 1, f"{prefix} runner did not create exactly one retained work directory")
    return physical_directory(created.pop(), f"{prefix} retained work")


def make_retained_readable(path: Path) -> None:
    """Make only newly retained evidence host-traversable before it is sealed."""
    path = physical_directory(path, "retained evidence root")
    for current in (path, *path.rglob("*")):
        mode = current.lstat().st_mode
        if stat.S_ISLNK(mode):
            continue
        if stat.S_ISDIR(mode):
            current.chmod(0o755)
        elif stat.S_ISREG(mode):
            current.chmod(0o755 if mode & 0o111 else 0o644)
        else:
            fail(f"retained evidence has unsupported file type: {current}")


def collect(*, base_inventory: Path, elf_report: Path, static_preparation: Path, static_product: Path,
            dynamic_product: Path, output: Path) -> dict[str, object]:
    """Run only the existing finite supplied-product workloads and seal their bytes."""
    inputs = validate_supplied_products(root=ROOT, base_inventory=base_inventory, elf_report=elf_report,
                                       static_preparation=static_preparation, static_product=static_product,
                                       dynamic_product=dynamic_product)
    output = Path(output).absolute()
    work_root = ROOT / ".work/x86_64"
    require(output.parent.is_relative_to(work_root) and not output.exists() and not output.is_symlink(),
            "component output must be a fresh checkout .work child")
    physical_directory(output.parent, "component output parent")
    output.mkdir(mode=0o700)
    source = inventory.collector_source_seal()
    environment = {**WORKLOAD_ENVIRONMENT, "TMPDIR": str(output), "CRABC_GENERAL_DYNAMIC_ENTRY_MODE": "--dynamic-pie",
                   DLFCN_SKIP_SEARCH_ENV: "1"}
    dlfcn: dict[str, object] = {}
    for mode in DLOPEN_MODES:
        before = set(output.glob("general-dynamic-dlopen.*"))
        environment["CRABC_GENERAL_DYNAMIC_ENTRY_MODE"] = f"--dynamic-{mode}"
        command = ["bash", str(ROOT / "compat/x86_64/run_general_dynamic_dlopen.sh"), str(Path(dynamic_product).absolute())]
        command_record = _capture(command, output=output, label=f"dlfcn-{mode}", environment=environment)
        work = _new_work(output, "general-dynamic-dlopen", before)
        make_retained_readable(work)
        observation = dlfcn_observations(Path(dynamic_product), output, work)
        require(observation["driver_mode"] == DLOPEN_DRIVER_MODES[mode],
                "general dlfcn driver receipt mode differs from requested mode")
        observation["entry_mode"] = mode
        dlfcn[mode] = {"command": command_record, "observation": observation}
    before = set(output.glob("general-dynamic-fork.*"))
    fork_command = _capture(["bash", str(ROOT / "compat/x86_64/run_general_dynamic_fork.sh"), str(Path(dynamic_product).absolute())],
                            output=output, label="fork", environment={**WORKLOAD_ENVIRONMENT, "TMPDIR": str(output)})
    fork_work = _new_work(output, "general-dynamic-fork", before)
    make_retained_readable(fork_work)
    fork_receipt = fork_evidence.validate_observations(Path(dynamic_product), fork_work)
    before = set(output.glob("owned-posix-timers.*"))
    timer_command = _capture(["bash", str(ROOT / "compat/x86_64/run_owned_posix_timers.sh"), str(Path(dynamic_product).absolute())],
                             output=output, label="timer-reset", environment={**WORKLOAD_ENVIRONMENT, "TMPDIR": str(output)})
    timer_work = _new_work(output, "owned-posix-timers", before)
    make_retained_readable(timer_work)
    timer = timer_observations(Path(dynamic_product), output, timer_work)
    require(source == inventory.collector_source_seal(), "collector source changed during runtime observations")
    report = {"schema": SCHEMA, "target": TARGET, "status": {"family_completion": False, "promotion_ready": False},
              "source": source, "source_files": source_records(ROOT), "inputs": inputs,
              "dlfcn": dlfcn, "fork": {"command": fork_command, "work": str(fork_work.relative_to(output)), "receipt": fork_receipt},
              "timer_reset": {"command": timer_command, "observation": timer}}
    (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    output.chmod(0o755)
    return report


def timer_observations(product: Path, output: Path, work: Path) -> dict[str, object]:
    """Join timer reset raw executions and existing owned-link receipts."""
    product, output, work = physical_directory(product, "dynamic product"), physical_directory(output, "component output"), physical_directory(work, "timer work")
    require(work.is_relative_to(output), "timer work escapes retained component output")
    app = timer_evidence.validate_timer_application_compile(product, ROOT / "compat/x86_64/owned_posix_timers_probe.c",
                                                            work / "probe.o", work / "probe.compile-audit.json")
    tls = timer_evidence.validate_timer_tls_dso(product, ROOT / "compat/x86_64/owned_posix_timers_tls.c", work / "tls.o",
                                                work / "tls.compile-audit.json", work / "libtimer-tls.so",
                                                work / "libtimer-tls.so.crabc-link.json")
    links = read_json(work / "link-identities.json", "timer link identities")
    require(links.get("schema") == "crabc.x86_64-owned-posix-timers-link-identities/v1" and isinstance(links.get("links"), dict),
            "timer link identity receipt drifted")
    observed: dict[str, object] = {}
    for mode in TIMER_MODES:
        require(mode in links["links"], f"timer link receipt omits dynamic {mode}")
        link = product_evidence.validate_link(product, work / "probe.o", work / f"dynamic-{mode}",
                                             work / f"dynamic-{mode}.crabc-link.json", mode)
        require(links["links"][mode] == link, f"timer {mode} link identity no longer reconstructs")
        cells = {}
        for entry, stem in (("kernel", f"dynamic-{mode}-ordinary.stdout"), ("direct", f"direct-{mode}-ordinary.stdout")):
            stdout = physical_regular(work / stem, f"timer {mode}/{entry} stdout")
            stderr = physical_regular(work / f"{stem}.stderr", f"timer {mode}/{entry} stderr")
            status = physical_regular(work / f"{stem}.status", f"timer {mode}/{entry} status")
            oracle = physical_regular(work / "oracle-dynamic.stdout", "timer oracle stdout")
            require(stdout.read_bytes() == oracle.read_bytes() and status.read_text(encoding="ascii") == "0\n",
                    f"timer {mode}/{entry} execution differs from oracle or failed")
            cells[entry] = {"stdout": identity(stdout, logical_path=(work / stem).relative_to(output).as_posix()),
                            "stderr": identity(stderr, logical_path=(work / f"{stem}.stderr").relative_to(output).as_posix()),
                            "status": identity(status, logical_path=(work / f"{stem}.status").relative_to(output).as_posix())}
        observed[mode] = {"link": link, "entries": cells}
    for stem in ("tls-reset-tests.stdout", "tls-import-tests.stdout"):
        status = physical_regular(work / f"{stem}.status", f"timer reset {stem} status")
        require(status.read_text(encoding="ascii") == "0\n", f"timer reset source test {stem} failed")
    return {"work": str(work.relative_to(output)), "application": app, "tls_dso": tls,
            "modes": observed, "operations": [RESET_NAME], "scenario": "dynamic-pie-and-non-pie-kernel-and-direct"}


def _validate_command(output: Path, record: object, label: str, argv: list[str], environment: Mapping[str, str]) -> None:
    row = exact(record, {"argv", "environment", "stdout", "stderr", "status"}, f"{label} command")
    require(row["argv"] == argv, f"{label} command argv drifted")
    require(row["environment"] == dict(environment), f"{label} command environment drifted")
    for suffix in ("stdout", "stderr", "status"):
        stream = _read_stream(output, row[suffix], f"raw/{label}.{suffix}")
        if suffix == "status":
            require(stream == b"0\n", f"{label} command did not succeed")


def validate_report(report_path: Path, *, base_inventory: Path, elf_report: Path, static_preparation: Path,
                    static_product: Path, dynamic_product: Path) -> dict[str, object]:
    """Rehash and reconstruct a finite retained supplied-product receipt."""
    report_path = physical_regular(report_path, "runtime registry report")
    output = physical_directory(report_path.parent, "runtime registry report root")
    report = exact(read_json(report_path, "runtime registry report"),
                   {"schema", "target", "status", "source", "source_files", "inputs", "dlfcn", "fork", "timer_reset"},
                   "runtime registry report")
    require(report["schema"] == SCHEMA and report["target"] == TARGET
            and same(report["status"], {"family_completion": False, "promotion_ready": False}),
            "runtime registry report identity or status drifted")
    require(report["source"] == inventory.collector_source_seal(), "runtime registry collector source drifted")
    validate_source_records(ROOT, report["source_files"])
    inputs = validate_supplied_products(root=ROOT, base_inventory=base_inventory, elf_report=elf_report,
                                       static_preparation=static_preparation, static_product=static_product,
                                       dynamic_product=dynamic_product)
    require(same(report["inputs"], inputs), "runtime registry supplied products/source drifted")
    dlfcn = exact(report["dlfcn"], set(DLOPEN_MODES), "general dlfcn mode roster")
    reconstructed: dict[str, object] = {}
    for mode in DLOPEN_MODES:
        record = exact(dlfcn[mode], {"command", "observation"}, f"general dlfcn {mode}")
        _validate_command(output, record["command"], f"dlfcn-{mode}",
                          ["bash", str(ROOT / "compat/x86_64/run_general_dynamic_dlopen.sh"), str(Path(dynamic_product).absolute())],
                          {**WORKLOAD_ENVIRONMENT, "TMPDIR": str(output), "CRABC_GENERAL_DYNAMIC_ENTRY_MODE": f"--dynamic-{mode}",
                           DLFCN_SKIP_SEARCH_ENV: "1"})
        observation = record["observation"]
        require(isinstance(observation, dict) and observation.get("entry_mode") == mode
                and observation.get("driver_mode") == DLOPEN_DRIVER_MODES[mode],
                f"general dlfcn {mode} receipt mode drifted")
        work = physical_directory(output / observation["work"], f"general dlfcn {mode} work")
        current = dlfcn_observations(Path(dynamic_product), output, work)
        current["entry_mode"] = mode
        require(same(observation, current), f"general dlfcn {mode} retained artifacts do not reconstruct")
        reconstructed[mode] = current
    fork = exact(report["fork"], {"command", "work", "receipt"}, "fork observation")
    _validate_command(output, fork["command"], "fork", ["bash", str(ROOT / "compat/x86_64/run_general_dynamic_fork.sh"), str(Path(dynamic_product).absolute())],
                      {**WORKLOAD_ENVIRONMENT, "TMPDIR": str(output)})
    fork_current = fork_evidence.validate_observations(Path(dynamic_product), physical_directory(output / fork["work"], "fork work"))
    require(same(fork["receipt"], fork_current), "fork retained receipt does not reconstruct")
    timer = exact(report["timer_reset"], {"command", "observation"}, "timer reset observation")
    _validate_command(output, timer["command"], "timer-reset", ["bash", str(ROOT / "compat/x86_64/run_owned_posix_timers.sh"), str(Path(dynamic_product).absolute())],
                      {**WORKLOAD_ENVIRONMENT, "TMPDIR": str(output)})
    timer_current = timer_observations(Path(dynamic_product), output,
                                       physical_directory(output / timer["observation"]["work"], "timer reset work"))
    require(same(timer["observation"], timer_current), "timer reset retained artifacts do not reconstruct")
    # Do not infer coverage from the runner names.  The report itself must name
    # each protocol operation/scenario and both required entry modes.
    covered = set()
    for observation in reconstructed.values():
        covered.update(observation["operations"])
    covered.update(fork_current.get("validation", {}).get("operations", []))
    # Fork's established v2 receipt has no operation list; its contract map is
    # explicit here, after the entire 100-cell reader has replayed.
    covered.update(FORK_NAMES)
    covered.update(timer_current["operations"])
    require(covered == set(RESOLVERS), "runtime registry operation coverage is incomplete")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", allow_abbrev=False)
    validate_parser = commands.add_parser("validate-report", allow_abbrev=False)
    for current in (collect_parser, validate_parser):
        current.add_argument("--base-inventory", type=Path, required=True)
        current.add_argument("--elf-report", type=Path, required=True)
        current.add_argument("--static-preparation", type=Path, required=True)
        current.add_argument("--static-product", type=Path, required=True)
        current.add_argument("--dynamic-product", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    validate_parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        fields = {name: getattr(args, name) for name in ("base_inventory", "elf_report", "static_preparation", "static_product", "dynamic_product")}
        if args.command == "collect":
            report = collect(**fields, output=args.output)
        else:
            report = validate_report(args.report, **fields)
        print(f"loader runtime registry evidence validated: {len(report['inputs']['imports'])} private imports; unqualified")
        return 0
    except (RuntimeRegistryEvidenceError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
