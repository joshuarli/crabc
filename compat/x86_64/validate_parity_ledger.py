#!/usr/bin/env python3
"""Validate the closed, non-symbol x86-64 runtime-parity ledger.

This is repository test infrastructure, not a runtime dependency.  It records
which AArch64 capability and gate families need independent native x86 proof;
it never treats a source-only foundation slice as public target support.
"""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
EXPECTED_SCHEMA = "crabc.x86_64-runtime-parity/v1"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_KERNEL_MSRV = "5.10"

EXPECTED_FAMILIES = (
    "oracle.musl-toolchain",
    "core.architecture",
    "facade.direct",
    "facade.record-owning",
    "libc.raw-syscall",
    "libc.errno-tls",
    "libc.headers-layouts",
    "libc.posix-runtime",
    "libc.pthread-tls",
    "libc.text-math-locale-stdio",
    "libc.resolver",
    "libc.c-abi-compat",
    "ldso.relative-relocation",
    "ldso.dynamic-runtime",
    "crt.static-pie",
    "crt.dynamic-startup",
    "sysroot.static-tls",
    "sysroot.owned-artifact",
    "compat.abi-differential",
    "compat.posix-process",
    "compat.resolver-network",
    "compat.loader-corpus",
    "consumer.rust-std-lto",
    "consumer.source-build",
    "capability.accounting",
    "performance.release",
)

ALLOWED_CATEGORIES = {
    "architecture-foundation",
    "rust-facade",
    "c-abi",
    "runtime-artifact",
    "compatibility-gate",
    "consumer-gate",
    "promotion-gate",
}
ALLOWED_STATUSES = {"foundation-verified", "planned"}
ALLOWED_EVIDENCE_STATES = {"verified", "required"}
KNOWN_AARCH64_GATES = {
    "abi-probe",
    "build",
    "compat",
    "corpus",
    "crabc-rs",
    "dashboard",
    "differential",
    "ldso",
    "libc-test",
    "loader-inventory",
    "lto",
    "lto-native-facade",
    "os-test",
    "perf",
    "perf-native",
    "pthread-stress",
    "resolver-network",
    "rust-std",
    "rust-std-dependent",
    "signal-process",
    "static-pthread-tls",
    "symbols",
    "sysroot",
    "sysroot-dist",
    "sysroot-smoke",
    "test",
    "lua",
}


class LedgerError(ValueError):
    """The parity ledger does not describe a reviewable closed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LedgerError(f"cannot load {path}: {error}") from error
    require(isinstance(data, dict), "ledger top level must be a table")
    return data


def nonempty_strings(value: Any, location: str) -> list[str]:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    result: list[str] = []
    for index, entry in enumerate(value):
        require(isinstance(entry, str) and entry, f"{location}[{index}] must be a non-empty string")
        result.append(entry)
    return result


def string_list(value: Any, location: str, *, allow_empty: bool = False) -> list[str]:
    """Return a string list while retaining a useful location in failures."""
    require(isinstance(value, list), f"{location} must be an array")
    require(allow_empty or bool(value), f"{location} must be a non-empty array")
    result: list[str] = []
    for index, entry in enumerate(value):
        require(isinstance(entry, str) and entry, f"{location}[{index}] must be a non-empty string")
        result.append(entry)
    return result


def repository_path(path_text: str, location: str) -> Path:
    require(isinstance(path_text, str) and path_text, f"{location} is empty")
    path = Path(path_text)
    require(not path.is_absolute(), f"{location} must be repository-relative: {path_text}")
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise LedgerError(f"{location} escapes the repository: {path_text}") from error
    require(resolved.exists(), f"{location} does not exist: {path_text}")
    return resolved


def require_evidence(
    value: Any, location: str, status: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    states: set[str] = set()
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        state = entry.get("state")
        command = entry.get("command")
        scope = entry.get("scope")
        require(state in ALLOWED_EVIDENCE_STATES, f"{item_location}.state is invalid")
        require(isinstance(command, str) and command, f"{item_location}.command is empty")
        require(isinstance(scope, str) and scope, f"{item_location}.scope is empty")
        states.add(state)
        records.append(entry)
    expected_state = "verified" if status == "foundation-verified" else "required"
    require(states == {expected_state}, f"{location} must be entirely {expected_state} for status {status}")
    return records, states


def require_oracles(value: Any, location: str) -> None:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in ("kind", "source", "role"):
            item = entry.get(key)
            require(isinstance(item, str) and item, f"{item_location}.{key} is empty")


def baseline_capability_ids(path: Path) -> set[str]:
    """Load the checked-in baseline ledger instead of freezing its ID count here."""
    baseline = load_toml(path)
    capabilities = baseline.get("capability")
    require(isinstance(capabilities, list) and capabilities, "baseline capability ledger has no capability records")
    identifiers: set[str] = set()
    for index, entry in enumerate(capabilities):
        location = f"baseline capability[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        identifier = entry.get("id")
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in identifiers, f"baseline capability ledger has duplicate id: {identifier}")
        identifiers.add(identifier)
    return identifiers


def has_musl_oracle(family: Mapping[str, Any]) -> bool:
    """Whether a parity family names musl as an oracle in its own contract."""
    records = family["oracle"]
    assert isinstance(records, list)
    return any(
        isinstance(record, Mapping)
        and isinstance(record.get("source"), str)
        and "musl" in record["source"].lower()
        for record in records
    )


def validate_ledger(data: Mapping[str, Any]) -> dict[str, Any]:
    require(data.get("schema") == EXPECTED_SCHEMA, "unexpected x86 parity ledger schema")
    require(data.get("target") == EXPECTED_TARGET, "unexpected x86 parity target")
    require(data.get("platform") == EXPECTED_PLATFORM, "unexpected x86 parity platform")
    require(data.get("kernel_msrv") == EXPECTED_KERNEL_MSRV, "unexpected x86 parity kernel MSRV")
    require(data.get("baseline_platform") == "Linux/AArch64 little-endian", "baseline platform changed")
    baseline_path = repository_path(str(data.get("baseline_capability_ledger", "")), "baseline_capability_ledger")
    repository_path(str(data.get("baseline_gate_dispatch", "")), "baseline_gate_dispatch")

    policy = data.get("policy")
    require(isinstance(policy, Mapping), "policy must be a table")
    expected_policy = {
        "native_execution_only": True,
        "public_support": False,
        "no_emulation": True,
        "no_portability_framework": True,
        "no_symbol_count_claim": True,
    }
    require(dict(policy) == expected_policy, "x86 parity policy drifted")

    meanings = data.get("status_meaning")
    require(isinstance(meanings, Mapping), "status_meaning must be a table")
    require(
        all(
            isinstance(meanings.get(name), str) and meanings[name]
            for name in ("foundation_verified", "planned")
        ),
        "status meanings are incomplete",
    )

    promotion = data.get("promotion")
    require(isinstance(promotion, Mapping), "promotion must be a table")
    required_families = nonempty_strings(promotion.get("required_families"), "promotion.required_families")
    require(tuple(required_families) == EXPECTED_FAMILIES, "promotion family roster drifted")

    excluded = data.get("excluded_surface")
    require(isinstance(excluded, list) and len(excluded) == 1, "exactly one excluded surface is required")
    excluded_entry = excluded[0]
    require(isinstance(excluded_entry, Mapping), "excluded_surface[0] must be a table")
    require(excluded_entry.get("id") == "allocator.mimalloc-private", "private allocator exclusion changed")
    require(isinstance(excluded_entry.get("reason"), str) and excluded_entry["reason"], "allocator exclusion needs a reason")
    for index, path_text in enumerate(nonempty_strings(excluded_entry.get("evidence"), "excluded_surface[0].evidence")):
        repository_path(path_text, f"excluded_surface[0].evidence[{index}]")

    families = data.get("family")
    require(isinstance(families, list), "family must be an array")
    require(len(families) == len(EXPECTED_FAMILIES), "family count drifted")
    ids: set[str] = set()
    orders: list[int] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    status_counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    for index, entry in enumerate(families):
        location = f"family[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        for key in (
            "id",
            "order",
            "depends_on",
            "category",
            "description",
            "aarch64_gates",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
            "capabilities",
            "status",
        ):
            require(key in entry, f"{location} is missing {key}")
        identifier = entry["id"]
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in ids, f"duplicate family id: {identifier}")
        require(identifier in EXPECTED_FAMILIES, f"unexpected family id: {identifier}")
        order = entry["order"]
        require(isinstance(order, int) and order > 0, f"{location}.order is invalid")
        category = entry["category"]
        status = entry["status"]
        require(category in ALLOWED_CATEGORIES, f"{location}.category is invalid")
        require(status in ALLOWED_STATUSES, f"{location}.status is invalid")
        require(isinstance(entry["description"], str) and entry["description"], f"{location}.description is empty")
        gates = nonempty_strings(entry["aarch64_gates"], f"{location}.aarch64_gates")
        unknown_gates = sorted(set(gates) - KNOWN_AARCH64_GATES)
        require(not unknown_gates, f"{location} names unknown AArch64 gates: {', '.join(unknown_gates)}")
        for owner_index, path_text in enumerate(nonempty_strings(entry["source_owners"], f"{location}.source_owners")):
            repository_path(path_text, f"{location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{location}.x86_header_prerequisites")
        require_evidence(entry["native_evidence"], f"{location}.native_evidence", status)
        require_oracles(entry["oracle"], f"{location}.oracle")
        ids.add(identifier)
        orders.append(order)
        by_id[identifier] = entry
        status_counts[status] += 1

    require(tuple(entry["id"] for entry in families) == EXPECTED_FAMILIES, "family table order must equal promotion dependency order")
    require(orders == sorted(orders) and len(orders) == len(set(orders)), "family order values must be unique and ascending")
    require(ids == set(EXPECTED_FAMILIES), "family coverage does not match promotion roster")

    musl_oracle = by_id["oracle.musl-toolchain"]
    require(musl_oracle["status"] == "foundation-verified", "musl oracle must remain foundation-verified")
    musl_evidence, _ = require_evidence(
        musl_oracle["native_evidence"], "family[oracle.musl-toolchain].native_evidence", musl_oracle["status"]
    )
    require(
        [entry["command"] for entry in musl_evidence] == ["./scripts/dev-x86_64.sh musl-oracle"],
        "musl oracle must use the closed native musl-oracle command",
    )
    for identifier, family in by_id.items():
        if identifier != "oracle.musl-toolchain" and has_musl_oracle(family):
            dependencies = family["depends_on"]
            assert isinstance(dependencies, list)
            require(
                "oracle.musl-toolchain" in dependencies,
                f"musl-backed family {identifier} must depend on oracle.musl-toolchain",
            )

    baseline_ids = baseline_capability_ids(baseline_path)
    capability_owners: dict[str, str] = {}
    for identifier, family in by_id.items():
        capabilities = string_list(
            family["capabilities"], f"family[{identifier}].capabilities", allow_empty=True
        )
        require(
            len(capabilities) == len(set(capabilities)),
            f"family[{identifier}] maps a capability more than once",
        )
        for capability in capabilities:
            previous = capability_owners.get(capability)
            require(
                previous is None,
                f"baseline capability {capability} is mapped by both {previous} and {identifier}",
            )
            capability_owners[capability] = identifier

    mapped_ids = set(capability_owners)
    stale_ids = sorted(mapped_ids - baseline_ids)
    missing_ids = sorted(baseline_ids - mapped_ids)
    require(not stale_ids, f"parity ledger maps stale baseline capabilities: {', '.join(stale_ids)}")
    require(not missing_ids, f"parity ledger leaves baseline capabilities unmapped: {', '.join(missing_ids)}")

    orders_by_id = {identifier: entry["order"] for identifier, entry in by_id.items()}
    for identifier, entry in by_id.items():
        dependencies = nonempty_strings(entry["depends_on"], f"family[{identifier}].depends_on") if entry["depends_on"] else []
        require(len(dependencies) == len(set(dependencies)), f"family[{identifier}] has duplicate dependencies")
        for dependency in dependencies:
            require(dependency in by_id, f"family[{identifier}] depends on unknown family {dependency}")
            require(orders_by_id[dependency] < orders_by_id[identifier], f"family[{identifier}] dependency {dependency} is not earlier")

    dispatch_source = (ROOT / "scripts" / "dev.sh").read_text(encoding="utf-8")
    used_gates = {gate for family in families for gate in family["aarch64_gates"]}
    missing_dispatch = sorted(gate for gate in used_gates if f"    {gate})" not in dispatch_source and f"    {gate}|" not in dispatch_source)
    require(not missing_dispatch, f"AArch64 gate dispatch does not contain: {', '.join(missing_dispatch)}")

    return {
        "schema": EXPECTED_SCHEMA,
        "family_count": len(families),
        "capability_count": len(baseline_ids),
        "capability_owners": capability_owners,
        "status_counts": status_counts,
        "promotion_ready": all(family["status"] == "foundation-verified" for family in families),
        "public_support": policy["public_support"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the checked-in ledger (default)")
    arguments = parser.parse_args()
    del arguments
    report = validate_ledger(load_toml(LEDGER_PATH))
    print(
        "x86 parity ledger: PASS "
        f"({report['family_count']} families; "
        f"foundation={report['status_counts']['foundation-verified']}; "
        f"planned={report['status_counts']['planned']}; "
        f"promotion_ready={report['promotion_ready']}; "
        f"public_support={report['public_support']})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        raise SystemExit(f"x86 parity ledger: ERROR: {error}") from error
