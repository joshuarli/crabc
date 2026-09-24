#!/usr/bin/env python3
"""Execute and assess the fixed, non-promoting native x86 `libc.c-abi-compat` family.

`run` executes every component of `c-abi-compat-family.toml` against the
primary static/dynamic pair of one current product cohort (a validated
`owned-posix-static-products` preparation plus a `materialized-dynamic-sysroot`
qualification on the same clean source). Each component is an existing
installed-product runner; its raw streams, status and single declared evidence
root are retained under the run directory whether or not it passes. The
retained assessment replays every component's reader, binds every product root
the evidence names to the cohort, accounts the family's libc-test units, and
records each failure as a named gap. The ledger admits the family only from a
complete retained assessment through `admission_facts`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tomllib
from typing import Any, Mapping

import owned_c_abi_compat_family_cohort as cohort
import owned_posix_family_execution as family


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-c-abi-compat-family/v1"
REQUEST_SCHEMA = "crabc.x86_64-owned-c-abi-compat-family-request/v1"
ROSTER_SCHEMA = "crabc.x86_64-owned-c-abi-compat-family-roster/v1"
FAMILY = "libc.c-abi-compat"
ROSTER = Path("compat/x86_64/c-abi-compat-family.toml")
LEDGER = Path("compat/x86_64/parity.toml")
DISPATCHER = "./scripts/dev-x86_64.sh"
EXECUTION_WORK = Path(".work/x86_64")
PRODUCT_SCOPES = {
    "static-and-dynamic": ("static", "static-pie", "pie", "non-pie"),
    "dynamic": ("pie", "non-pie"),
}
READER_KINDS = ("runner", "crypt-profile", "differential", "libc-test")
DISPOSITIONS = {"crypt-profile": "crypt-profile"}
STATIC_LINKAGES = frozenset(("static", "static-pie"))
# Enough raw context to name a failed component's condition in the assessment;
# the complete streams stay retained beside it.
FAILURE_TAIL_LINES = 12


class CAbiCompatFamilyError(RuntimeError):
    """A required c-abi-compat family input is absent, mutable, or malformed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CAbiCompatFamilyError(message)


@dataclass(frozen=True)
class Component:
    identifier: str
    command: str | None
    runner: str
    products: str
    reader: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class LibcTestUnit:
    identifier: str
    capabilities: tuple[str, ...]
    disposition: str | None
    companion: str | None


@dataclass(frozen=True)
class Roster:
    capabilities: tuple[str, ...]
    components: tuple[Component, ...]
    libc_test_units: tuple[LibcTestUnit, ...]

    def component(self, identifier: str) -> Component:
        return next(component for component in self.components if component.identifier == identifier)


def _strings(value: object, description: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    require(isinstance(value, list) and (allow_empty or value)
            and all(isinstance(item, str) and item for item in value),
            f"{description} must be a non-empty string list")
    result = tuple(value)
    require(len(result) == len(set(result)), f"{description} is duplicated")
    return result


def _load_toml(path: Path, description: str) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CAbiCompatFamilyError(f"cannot parse {description}: {error}") from error


def _tracked_identity(root: Path, relative: Path) -> dict[str, object]:
    """Identify one committed checkout file outside `.work`."""

    path = root / relative
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            f"{relative} is not a physical checkout file")
    data = path.read_bytes()
    return {"path": relative.as_posix(), "sha256": sha256(data).hexdigest(),
            "byte_length": len(data), "mode": stat.S_IMODE(path.stat().st_mode)}


def _ledger_family(root: Path) -> Mapping[str, Any]:
    rows = _load_toml(root / LEDGER, "x86 parity ledger").get("family")
    require(isinstance(rows, list), "x86 parity ledger has no families")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == FAMILY]
    require(len(matches) == 1, f"x86 parity ledger does not map exactly one {FAMILY}")
    return matches[0]


def _slice_commands(ledger_family: Mapping[str, Any]) -> dict[str, set[str]]:
    """Map every installed-product command a verified slice cites to its capabilities."""

    cited: dict[str, set[str]] = {}
    for row in ledger_family.get("verified_slice", []):
        capabilities = set(_strings(row.get("capabilities"), f"{FAMILY} slice capabilities"))
        for entry in row.get("native_evidence", []):
            command = entry.get("command") if isinstance(entry, dict) else None
            require(isinstance(command, str), f"{FAMILY} slice evidence command is malformed")
            words = command.split()
            if len(words) >= 2 and words[0] == DISPATCHER and words[1].startswith("owned-"):
                cited.setdefault(words[1], set()).update(capabilities)
    return cited


def load_roster(root: Path) -> Roster:
    """Read the fixed roster and join it to the family's ledger row.

    The ledger row, not the roster, names the family's capabilities. Every
    `owned-*` command a verified slice cites must be a component that credits
    that slice's capabilities, and every capability a component with a ledger
    command credits must be cited by a slice for that capability.
    """

    raw = _load_toml(root / ROSTER, "c-abi-compat family roster")
    require(raw.get("schema") == ROSTER_SCHEMA and raw.get("family") == FAMILY,
            "c-abi-compat family roster identity differs")
    ledger_family = _ledger_family(root)
    capabilities = _strings(ledger_family.get("capabilities"), f"{FAMILY} ledger capabilities")

    unit_rows = raw.get("libc_test_unit")
    require(isinstance(unit_rows, list) and unit_rows, "c-abi-compat libc-test unit roster is absent")
    units: list[LibcTestUnit] = []
    for row in unit_rows:
        require(isinstance(row, dict) and set(row) <= {"id", "capabilities", "disposition", "companion"},
                "c-abi-compat libc-test unit is malformed")
        identifier = row.get("id")
        require(isinstance(identifier, str) and identifier.count("/") == 1,
                "c-abi-compat libc-test unit identifier differs")
        disposition, companion = row.get("disposition"), row.get("companion")
        require((disposition is None) == (companion is None) and disposition in (None, *DISPOSITIONS),
                f"c-abi-compat libc-test unit {identifier} disposition differs")
        units.append(LibcTestUnit(identifier, _strings(row.get("capabilities"), f"libc-test unit {identifier}"),
                                  disposition, companion))
    require(len({unit.identifier for unit in units}) == len(units), "c-abi-compat libc-test unit is duplicated")
    unit_capabilities = tuple(sorted({capability for unit in units for capability in unit.capabilities}))

    component_rows = raw.get("component")
    require(isinstance(component_rows, list) and component_rows, "c-abi-compat component roster is absent")
    components: list[Component] = []
    for row in component_rows:
        require(isinstance(row, dict), "c-abi-compat component is malformed")
        identifier, reader = row.get("id"), row.get("reader")
        require(isinstance(identifier, str) and identifier, "c-abi-compat component identifier differs")
        require(reader in READER_KINDS, f"c-abi-compat component {identifier} reader differs")
        allowed = {"id", "command", "runner", "products", "reader"} | ({"capabilities"} if reader != "libc-test" else set())
        require(set(row) <= allowed, f"c-abi-compat component {identifier} fields differ")
        command, runner, products = row.get("command"), row.get("runner"), row.get("products")
        require(command is None or (isinstance(command, str) and command.startswith("owned-")),
                f"c-abi-compat component {identifier} command differs")
        require(isinstance(runner, str) and runner.startswith("compat/x86_64/run_") and runner.endswith(".sh"),
                f"c-abi-compat component {identifier} runner differs")
        _tracked_identity(root, Path(runner))
        require(products in PRODUCT_SCOPES, f"c-abi-compat component {identifier} product scope differs")
        require(reader not in ("differential", "libc-test") or products == "dynamic",
                f"c-abi-compat component {identifier} reader requires the dynamic product only")
        credited = unit_capabilities if reader == "libc-test" else _strings(
            row.get("capabilities"), f"c-abi-compat component {identifier} capabilities")
        components.append(Component(identifier, command, runner, products, reader, credited))
    identifiers = [component.identifier for component in components]
    require(len(identifiers) == len(set(identifiers)), "c-abi-compat component is duplicated")
    require(sum(component.reader == "libc-test" for component in components) == 1,
            "c-abi-compat family needs exactly one libc-test accounting component")
    for unit in units:
        if unit.companion is not None:
            require(unit.companion in identifiers and next(
                component for component in components if component.identifier == unit.companion
            ).reader == DISPOSITIONS[unit.disposition],
                    f"c-abi-compat libc-test unit {unit.identifier} companion differs")

    for component in components:
        unknown = set(component.capabilities) - set(capabilities)
        require(not unknown, f"c-abi-compat component {component.identifier} credits a foreign capability: "
                             + ", ".join(sorted(unknown)))
    for capability in capabilities:
        require(any(capability in component.capabilities for component in components),
                f"c-abi-compat capability {capability} has no component")

    commands = {component.command: component for component in components if component.command is not None}
    require(len(commands) == sum(component.command is not None for component in components),
            "c-abi-compat component command is duplicated")
    cited = _slice_commands(ledger_family)
    for command, slice_capabilities in sorted(cited.items()):
        require(command in commands, f"verified slice command {command} is not a c-abi-compat component")
        missing = slice_capabilities - set(commands[command].capabilities)
        require(not missing, f"c-abi-compat component {commands[command].identifier} omits "
                             f"slice capabilities: {', '.join(sorted(missing))}")
    for command, component in commands.items():
        uncited = set(component.capabilities) - cited.get(command, set())
        require(not uncited, f"c-abi-compat component {component.identifier} credits capabilities no slice "
                             f"cites for {command}: {', '.join(sorted(uncited))}")
    return Roster(capabilities, tuple(components), tuple(units))


def frozen_capabilities(root: Path, capabilities: tuple[str, ...]) -> dict[str, dict[str, object]]:
    """Project the frozen AArch64 capability rows after checking their digest."""

    baseline = json.loads((root / "compat/x86_64/aarch64_frozen_baseline.json").read_text(encoding="utf-8"))
    record = baseline.get("aarch64_inputs", {}).get("capability_ledger")
    ledger = root / "compat/crabc-rs/coverage.toml"
    require(isinstance(record, dict) and record.get("path") == "compat/crabc-rs/coverage.toml"
            and record.get("sha256") == sha256(ledger.read_bytes()).hexdigest(),
            "frozen capability ledger has drifted")
    found: dict[str, dict[str, object]] = {}
    for row in _load_toml(ledger, "frozen capability ledger").get("capability", []):
        if isinstance(row, dict) and row.get("id") in capabilities:
            require(row["id"] not in found, f"frozen capability {row['id']} is duplicated")
            found[row["id"]] = {key: row.get(key) for key in ("kind", "classification", "status")} | {
                "symbols": row.get("symbols", [])}
    require(set(found) == set(capabilities), "frozen c-abi-compat capability set differs")
    return {capability: found[capability] for capability in capabilities}


# ---------------------------------------------------------------------------
# Execution


def _mounted(root: Path, path: Path, mount: str) -> str:
    return family.mounted(root, path, mount)


def _checkout_relative(value: object, mount: str, description: str) -> str:
    """Map one retained source-mount path back to its checkout-relative form."""

    prefix = mount.rstrip("/") + "/"
    require(isinstance(value, str) and value.startswith(prefix), f"{description} escapes the source mount")
    relative = Path(value[len(prefix):])
    require(relative.parts and ".." not in relative.parts, f"{description} path is malformed")
    return relative.as_posix()


def component_command(root: Path, component: Component, products: Mapping[str, Mapping[str, Any]],
                      mount: str) -> list[str]:
    """Invoke one existing runner on the primary pair: `[--static-sysroot S] D`."""

    primary = products[cohort.PAIR]
    command = ["bash", str(Path(mount) / component.runner)]
    if component.products == "static-and-dynamic":
        command += ["--static-sysroot", _mounted(root, root / primary["static"]["path"], mount)]
    command.append(_mounted(root, root / primary["dynamic"]["path"], mount))
    return command


def _product_seal(root: Path, products: Mapping[str, Mapping[str, Any]]) -> dict[str, object]:
    primary = products[cohort.PAIR]
    return {kind: {"manifest": primary[kind]["manifest"], "tree": family.snapshot(root / primary[kind]["path"])}
            for kind in cohort.KINDS}


def _request(root: Path, work: Path) -> dict[str, str]:
    request = family.read(work / "request.json")
    require(isinstance(request, dict) and set(request) == {
        "schema", "source_mount", "static_preparation", "dynamic_qualification"},
        "c-abi-compat family request fields differ")
    require(request["schema"] == REQUEST_SCHEMA, "c-abi-compat family request schema differs")
    mount = request["source_mount"]
    require(isinstance(mount, str) and Path(mount).is_absolute() and ".." not in Path(mount).parts
            and str(Path(mount)) == mount, "c-abi-compat family source mount differs")
    for name in ("static_preparation", "dynamic_qualification"):
        value = request[name]
        require(isinstance(value, str) and value and not Path(value).is_absolute()
                and ".." not in Path(value).parts, f"c-abi-compat family {name} path differs")
    return request


def _guard(root: Path, work: Path, products: Mapping[str, Mapping[str, Any]]) -> None:
    require(family.same_json(family.static_products.source_identity(root),
                             family.read(work / "source-before.json")),
            "source changed during c-abi-compat family execution")
    require(family.same_json(_product_seal(root, products), family.read(work / "product-before.json")),
            "primary product changed during c-abi-compat family execution")


def execute(root: Path, work: Path, static_preparation: Path, dynamic_qualification: Path) -> Path:
    """Run every component into a fresh `work` and retain its assessment.

    Component failures are retained, not fatal: each runner's raw evidence
    stays beside the next one, and the assessment names every gap. A changed
    source or product aborts the run because later evidence could not be
    attributed to the planned cohort.
    """

    root = root.resolve(strict=True)
    work = Path(os.path.abspath(root / work))
    require(work.is_relative_to(root / EXECUTION_WORK) and work != root / EXECUTION_WORK,
            "c-abi-compat family output must be below checkout .work/x86_64")
    require(not work.exists() and not work.is_symlink(), "c-abi-compat family output must be fresh")
    roster = load_roster(root)
    request = {
        "schema": REQUEST_SCHEMA,
        "source_mount": str(root),
        "static_preparation": family.physical(root, root / static_preparation).relative_to(root).as_posix(),
        "dynamic_qualification": family.physical(root, root / dynamic_qualification).relative_to(root).as_posix(),
    }
    _, products = cohort.canonical_products(root, root / request["static_preparation"],
                                            root / request["dynamic_qualification"])
    work.mkdir()
    family.static_products.write_new(work / "request.json", request)
    family.static_products.write_new(work / "source-before.json", family.static_products.source_identity(root))
    family.static_products.write_new(work / "product-before.json", _product_seal(root, products))
    companions: dict[str, Mapping[str, object]] = {}
    try:
        for component in roster.components:
            _guard(root, work, products)
            step = work / "runs" / component.identifier
            step.parent.mkdir(exist_ok=True)
            print(f"c-abi-compat family {component.identifier}: running", flush=True)
            try:
                family.run_step(root, step, component_command(root, component, products, str(root)),
                                family.case_environment(root, step, str(root)))
            except family.ExecutionError:
                pass
            finally:
                if step.exists():
                    family.static_products.make_retained_evidence_readable(step)
            result = component_result(root, work, component, products, str(root), roster, companions)
            family.static_products.write_new(step / "receipt.json", result)
            if result["admitted"] and component.reader == "crypt-profile":
                companions[component.identifier] = result["result"]
            print(f"c-abi-compat family {component.identifier}: "
                  + ("PASS" if result["admitted"] else f"GAP ({result['gap']['reason']})"), flush=True)
    finally:
        for name, capture in (("source-after.json", lambda: family.static_products.source_identity(root)),
                              ("product-after.json", lambda: _product_seal(root, products))):
            try:
                family.static_products.write_new(work / name, capture())
            except Exception as error:  # retain the failed seal instead of hiding the run
                family.static_products.write_new(work / (name[:-5] + "-error.json"), {"error": str(error)})
        family.static_products.make_retained_evidence_readable(work)
    path = work / "assessment.json"
    family.static_products.write_new(path, collect(root, work))
    path.chmod(0o444)
    return path


# ---------------------------------------------------------------------------
# Component readers


def _tail(path: Path) -> list[str]:
    try:
        lines = path.read_bytes().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[-FAILURE_TAIL_LINES:]


def _leaf(root: Path, step: Path, mount: str, component: Component) -> Path:
    """Admit exactly the one evidence root the runner declared in its scratch."""

    if component.reader != "libc-test":
        return family.leaf_directory(root, step, mount)
    # The libc-test leaf prints only its evidence path.
    prefix = mount.rstrip("/") + "/"
    leaves = set()
    for line in (step / "stdout").read_text(errors="replace").splitlines():
        if line.startswith(prefix) and Path(line).name.startswith("owned-libc-test."):
            leaves.add(family.physical(root, root / line[len(prefix):]))
    require(len(leaves) == 1, "libc-test must declare one retained evidence root")
    leaf = leaves.pop()
    require(leaf.is_dir() and leaf.parent == step / "tmp" and set((step / "tmp").iterdir()) == {leaf},
            "libc-test evidence escapes its exact step scratch")
    return leaf


def _declared_products(root: Path, mount: str, component: Component, command: list[str],
                       leaf: Path) -> dict[str, list[str]]:
    """Collect every product root the invocation and retained links name.

    A runner that retains sealed-link identities must retain one for every
    linkage its product scope exercises, each naming its product's current
    manifest.
    """

    declared: dict[str, list[str]] = {"static": [], "dynamic": []}
    if component.products == "static-and-dynamic":
        declared["static"].append(_checkout_relative(command[3], mount, f"{component.identifier} static argument"))
    declared["dynamic"].append(_checkout_relative(command[-1], mount, f"{component.identifier} dynamic argument"))
    linkages = set()
    for path in sorted(leaf.glob("*.link-identity.json")):
        identity = family.read(path)
        require(isinstance(identity, dict) and identity.get("linkage") in PRODUCT_SCOPES["static-and-dynamic"],
                f"{component.identifier} link identity is malformed: {path.name}")
        linkage = identity["linkage"]
        require(linkage not in linkages, f"{component.identifier} link identity is duplicated: {linkage}")
        linkages.add(linkage)
        product = _checkout_relative(identity.get("product"), mount, f"{component.identifier} {linkage} product")
        require(identity.get("product_manifest_sha256") == family.digest(root / product / "share/crabc/manifest.json"),
                f"{component.identifier} {linkage} link identity manifest differs from its product")
        declared["static" if linkage in STATIC_LINKAGES else "dynamic"].append(product)
    require(not linkages or linkages == set(PRODUCT_SCOPES[component.products]),
            f"{component.identifier} link identities do not cover its product modes")
    return declared


def _crypt_reader(root: Path, leaf: Path, mount: str, dynamic: Path, **_: object) -> dict[str, object]:
    import owned_crypt_profile as crypt

    path = leaf / "crypt-profile.json"
    record = crypt.validate_receipt(root, path, product=dynamic)
    return {"reader_schema": crypt.SCHEMA, "receipt": family.file_identity(root, path),
            "status": record["status"], "vectors": record["vectors"]}


def _differential_reader(root: Path, leaf: Path, mount: str, dynamic: Path, **_: object) -> dict[str, object]:
    import owned_posix_native_observations as native

    try:
        observed = native.collect("differential", leaf, source_mount=mount, dynamic_product=dynamic, root=root)
    except native.NativeObservationError as error:
        raise CAbiCompatFamilyError(str(error)) from error
    require(observed["qualification"] == {"status": "passed", "raw_passed": True, "dispositions": []},
            "differential qualification differs")
    return {"report": observed["report"], "product": observed["product"],
            "cases": sorted(observed["observations"])}


def _libc_test_reader(root: Path, leaf: Path, mount: str, dynamic: Path, *, status: int, roster: Roster,
                      companions: Mapping[str, Mapping[str, object]], **_: object) -> dict[str, object]:
    """Account the family's libc-test units in one retained campaign report.

    Units outside the roster belong to other families; this reader neither
    credits nor waives them. Every accounted unit must pass through the same
    retained translation and raw runtime records the complete native reader
    checks, except `functional/crypt`, which qualifies only through the fixed
    crypt disposition against this run's admitted crypt profile companion.
    """

    import owned_libc_test as contract
    import owned_posix_native_dispositions as profile
    import owned_posix_native_observations as native

    try:
        reader = native.Reader(leaf, mount, dynamic, root)
        report = native.read_json(leaf / "libc-test.json")
        native.same({key: report.get(key) for key in ("schema", "campaign_complete", "public_support", "target")},
                    {"schema": contract.SCHEMA, "campaign_complete": False, "public_support": False,
                     "target": contract.TARGET}, "libc-test campaign identity")
        native.same(report.get("status"), "passed" if status == 0 else "incomplete", "libc-test outer status")
        native.require("fatal_error" not in report and report.get("candidate_link_blocker") is None,
                       "libc-test campaign has a retained blocker")
        native._libc_product(reader, report)
        definitions, _ = native._libc_test_source(reader, report, contract)
        records = {record["id"]: record for record in report["units"]}
        kinds = {definition["id"]: definition for definition in definitions}
        accounted: dict[str, object] = {}
        for unit in roster.libc_test_units:
            native.require(unit.identifier in kinds, f"libc-test has no unit {unit.identifier}")
            definition, record = kinds[unit.identifier], records[unit.identifier]
            kind = definition["kind"]
            native.same([record["kind"], record["suite"]], [kind, definition["suite"]],
                        f"libc-test {unit.identifier} role")
            translation, header = record["candidate_translation"], record["header_translation"]
            native.same([translation["status"], header["status"], header["foreign_headers"]],
                        ["passed", "passed", []], f"libc-test {unit.identifier} translation")
            obj = leaf / "objects/candidate" / (unit.identifier + ".o")
            reader.bind(translation["object"], obj, f"libc-test {unit.identifier} object")
            if kind == "api":
                native.require(unit.disposition is None, f"libc-test {unit.identifier} api unit has a disposition")
                native.same(record["status"], "passed", f"libc-test {unit.identifier} status")
                accounted[unit.identifier] = {"kind": kind, "status": "passed", "object": reader.identity(obj)}
                continue
            native.same(kind, "runtime", f"libc-test {unit.identifier} kind")
            runtime, results, raw = record["runtime"], {}, {}
            for side in ("oracle", "candidate"):
                run = runtime[side]
                failed = unit.disposition is not None and side == "candidate"
                native.same([run["status"], run["root_reclaimed"]], ["failed" if failed else "passed", True],
                            f"libc-test {unit.identifier} {side} result")
                status_path = leaf / "execution" / unit.identifier / (side + ".status.json")
                reader.bind(run["status_record"], status_path, f"libc-test {unit.identifier} {side} status")
                native.same(native.read_json(status_path), run["record"], f"libc-test {unit.identifier} {side} record")
                results[side] = native._command_streams(reader, run["record"], expected_status=1 if failed else 0)
                raw[side] = [native.read_bytes(reader.local(run["record"][stream]["path"]))
                             for stream in ("stdout", "stderr")]
            if unit.disposition is None:
                native.same(record["status"], "passed", f"libc-test {unit.identifier} status")
                native.same(runtime["comparison"], {"status": "passed", "detail": "passed"},
                            f"libc-test {unit.identifier} comparison")
                native.require(raw["oracle"] == raw["candidate"], f"libc-test {unit.identifier} raw streams differ")
                accounted[unit.identifier] = {"kind": kind, "status": "passed", **results}
                continue
            companion = companions.get(unit.companion)
            native.require(companion is not None,
                           f"libc-test {unit.identifier} needs the admitted {unit.companion} companion")
            native.same(record["status"], "runtime-failed", f"libc-test {unit.identifier} status")
            native.same(runtime["comparison"],
                        {"status": "blocked", "reason": "candidate runtime did not pass this prepared root"},
                        f"libc-test {unit.identifier} comparison")
            disposition = profile.crypt_disposition(
                reader, leaf / "source-prepared" / definition["source"],
                candidate_status=runtime["candidate"]["record"]["exit_status"],
                candidate_stdout=raw["candidate"][0], candidate_stderr=raw["candidate"][1],
                oracle_status=runtime["oracle"]["record"]["exit_status"],
                oracle_stdout=raw["oracle"][0], oracle_stderr=raw["oracle"][1],
                companion={"receipt": companion["receipt"], "vectors": companion["vectors"]})
            accounted[unit.identifier] = {"kind": kind, "status": "profile-qualified", **results,
                                          "disposition": disposition}
    except (native.NativeObservationError, KeyError, TypeError, IndexError) as error:
        raise CAbiCompatFamilyError(f"libc-test accounting rejected: {error}") from error
    return {"report": reader.identity(leaf / "libc-test.json"), "campaign_status": report["status"],
            "counts": report["counts"], "units": accounted}


def _runner_reader(**_: object) -> dict[str, object]:
    return {}


READERS = {
    "runner": _runner_reader,
    "crypt-profile": _crypt_reader,
    "differential": _differential_reader,
    "libc-test": _libc_test_reader,
}


def _snapshot_identity(leaf: Path) -> dict[str, object]:
    nodes = family.snapshot(leaf)
    return {"entries": len(nodes),
            "sha256": sha256(json.dumps(nodes, sort_keys=True, allow_nan=False).encode()).hexdigest()}


def component_result(root: Path, work: Path, component: Component, products: Mapping[str, Mapping[str, Any]],
                     mount: str, roster: Roster, companions: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    """Reconstruct one component's admission, or the named condition it failed."""

    base = {"runner": component.runner, "products": component.products, "reader": component.reader,
            "capabilities": list(component.capabilities)}
    step = work / "runs" / component.identifier
    if not step.is_dir():
        return {**base, "admitted": False, "gap": {"component": component.identifier, "reason": "component-not-run"}}
    command = component_command(root, component, products, mount)
    try:
        require(family.same_json(family.read(step / "invocation.json"),
                                 family.invocation(Path(mount), command, family.case_environment(root, step, mount))),
                "component invocation differs from the cohort command")
        status_text = (step / "status").read_text(encoding="ascii")
        require(status_text.endswith("\n") and status_text[:-1].lstrip("-").isdigit(), "component status is malformed")
        status = int(status_text)
        execution = {name: family.file_identity(root, step / name)
                     for name in ("invocation.json", "stdout", "stderr", "status")}
    except (CAbiCompatFamilyError, family.ExecutionError, OSError, ValueError) as error:
        return {**base, "admitted": False, "gap": {"component": component.identifier,
                                                  "reason": "component-evidence-rejected", "detail": str(error)}}
    if status != 0 and not (component.reader == "libc-test" and status == 1):
        return {**base, "admitted": False, "execution": execution, "gap": {
            "component": component.identifier, "reason": "component-run-failed", "status": status,
            "stderr_tail": _tail(step / "stderr"), "stdout_tail": _tail(step / "stdout")}}
    try:
        leaf = _leaf(root, step, mount, component)
        dynamic = root / products[cohort.PAIR]["dynamic"]["path"]
        observed = READERS[component.reader](root=root, leaf=leaf, mount=mount, dynamic=dynamic, status=status,
                                             roster=roster, companions=companions)
        declared = _declared_products(root, mount, component, command, leaf)
        binding = cohort.bind_component(root, component.identifier, declared, products)
        artifacts = _snapshot_identity(leaf)
    except (CAbiCompatFamilyError, cohort.CAbiCompatFamilyCohortError, family.ExecutionError,
            OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        return {**base, "admitted": False, "execution": execution, "gap": {
            "component": component.identifier, "reason": "component-evidence-rejected", "detail": str(error)}}
    return {**base, "admitted": True, "execution": execution, "leaf": leaf.relative_to(root).as_posix(),
            "artifacts": artifacts, "cohort_binding": binding, "result": observed}


# ---------------------------------------------------------------------------
# Assessment


def collect(root: Path, work: Path) -> dict[str, object]:
    """Reconstruct the complete, possibly incomplete family assessment."""

    root = root.resolve(strict=True)
    work = family.physical(root, work)
    roster = load_roster(root)
    frozen = frozen_capabilities(root, roster.capabilities)
    request = _request(root, work)
    mount = request["source_mount"]
    source, products = cohort.canonical_products(root, root / request["static_preparation"],
                                                 root / request["dynamic_qualification"])
    current = family.static_products.source_identity(root)
    seals = {}
    for name in ("source-before.json", "source-after.json"):
        require(family.same_json(family.read(work / name), current), f"c-abi-compat family {name} differs")
        seals[name] = family.file_identity(root, work / name)
    product_seal = _product_seal(root, products)
    for name in ("product-before.json", "product-after.json"):
        require(family.same_json(family.read(work / name), product_seal), f"c-abi-compat family {name} differs")
        seals[name] = family.file_identity(root, work / name)
    expected_runs = {component.identifier for component in roster.components}
    runs = work / "runs"
    require(not runs.exists() or {path.name for path in runs.iterdir()} <= expected_runs,
            "c-abi-compat family run roster has an undeclared component")

    components: dict[str, dict[str, object]] = {}
    companions: dict[str, Mapping[str, object]] = {}
    for component in roster.components:
        result = component_result(root, work, component, products, mount, roster, companions)
        receipt = runs / component.identifier / "receipt.json"
        if (runs / component.identifier).is_dir():
            require(family.same_json(family.read(receipt), result),
                    f"c-abi-compat component receipt changed: {component.identifier}")
            result = {**result, "receipt": family.file_identity(root, receipt)}
        components[component.identifier] = result
        if result["admitted"] and component.reader == "crypt-profile":
            companions[component.identifier] = result["result"]
    gaps = [result["gap"] for result in components.values() if not result["admitted"]]
    capabilities = {
        capability: {
            "frozen": frozen[capability],
            "components": [component.identifier for component in roster.components
                           if capability in component.capabilities],
            "libc_test_units": [unit.identifier for unit in roster.libc_test_units
                                if capability in unit.capabilities],
        }
        for capability in roster.capabilities
    }
    for record in capabilities.values():
        record["admitted"] = all(components[identifier]["admitted"] for identifier in record["components"])
    return {
        "schema": SCHEMA,
        "family": FAMILY,
        "contract": _tracked_identity(root, ROSTER),
        "request": family.file_identity(root, work / "request.json"),
        "cohort": {"schema": cohort.SCHEMA, "source": source, "products": products},
        "seals": seals,
        "capabilities": capabilities,
        "components": components,
        "gaps": gaps,
        "family_complete": not gaps and all(record["admitted"] for record in capabilities.values()),
        "promotion_ready": False,
        "public_support": False,
    }


def validate_assessment(root: Path, path: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    path = family.physical(root, root / path)
    require(path.name == "assessment.json", "expected a c-abi-compat family assessment.json")
    reconstructed = collect(root, path.parent)
    require(family.same_json(family.read(path), reconstructed), "c-abi-compat family assessment does not reconstruct")
    return reconstructed


def admission_facts(root: Path, assessment_path: Path) -> dict[str, object]:
    """Check one retained complete assessment against current checkout bytes.

    Full reconstruction replays component readers in the pinned `/workspace`
    image, so the host ledger does not. It does reject an assessment whose
    contract, request, cohort receipts, admissions, or selected source no
    longer match this checkout, and returns the cohort receipt identities the
    ledger joins to the admitted POSIX family.
    """

    root = root.resolve(strict=True)
    path = family.physical(root, root / assessment_path)
    retained = family.read(path)
    require(isinstance(retained, dict) and retained.get("schema") == SCHEMA and retained.get("family") == FAMILY,
            "c-abi-compat family assessment identity differs")
    require(retained.get("family_complete") is True and retained.get("gaps") == []
            and retained.get("promotion_ready") is False and retained.get("public_support") is False,
            "c-abi-compat family assessment completion boundary differs")
    require(retained.get("contract") == _tracked_identity(root, ROSTER),
            "c-abi-compat family assessment contract changed")
    request = retained.get("request")
    require(isinstance(request, dict) and isinstance(request.get("path"), str)
            and family.same_json(family.file_identity(root, root / request["path"]), request),
            "c-abi-compat family assessment request changed")
    roster = load_roster(root)
    components = retained.get("components")
    require(isinstance(components, dict) and set(components) == {c.identifier for c in roster.components}
            and all(isinstance(value, dict) and value.get("admitted") is True for value in components.values()),
            "c-abi-compat family assessment component admission differs")
    capabilities = retained.get("capabilities")
    require(isinstance(capabilities, dict) and set(capabilities) == set(roster.capabilities)
            and all(isinstance(value, dict) and value.get("admitted") is True for value in capabilities.values()),
            "c-abi-compat family assessment capability admission differs")
    seal = retained.get("cohort", {}).get("source") if isinstance(retained.get("cohort"), dict) else None
    require(isinstance(seal, dict), "c-abi-compat family assessment cohort differs")
    current = family.static_products.source_identity(root)
    require(seal.get("revision") == current["revision"] and seal.get("content_sha256") == current["content_sha256"],
            "c-abi-compat family assessment is not bound to current source")
    receipts: dict[str, dict[str, object]] = {}
    for name in ("static_preparation", "dynamic_qualification"):
        record = seal.get(name)
        require(isinstance(record, dict) and isinstance(record.get("path"), str),
                f"c-abi-compat family assessment {name} identity differs")
        path_value = Path(record["path"])
        require(not path_value.is_absolute() and ".." not in path_value.parts,
                f"c-abi-compat family {name} path differs")
        observed = cohort.canonical._file_identity(root, root / path_value, f"c-abi-compat family {name}")
        require(observed == record, f"c-abi-compat family {name} receipt changed")
        receipts[name] = record
    return {"assessment": family.file_identity(root, path), "source": current, **receipts}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="execute every component on one cohort and retain its assessment")
    run.add_argument("--static-preparation", type=Path, required=True)
    run.add_argument("--dynamic-qualification", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    assess = commands.add_parser("assess", help="reconstruct a retained run without executing a workload")
    assess.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="reconstruct an assessment and require complete evidence")
    validate.add_argument("--assessment", type=Path, required=True)
    values = parser.parse_args()
    try:
        if values.command == "run":
            path = execute(ROOT, _checkout_path(values.output), _checkout_path(values.static_preparation),
                           _checkout_path(values.dynamic_qualification))
            print(path)
            assessment = family.read(path)
        elif values.command == "assess":
            print(json.dumps(collect(ROOT, ROOT / _checkout_path(values.output)), sort_keys=True))
            return 0
        else:
            assessment = validate_assessment(ROOT, _checkout_path(values.assessment))
        for identifier, result in assessment["components"].items():
            gap = result.get("gap")
            print(f"c-abi-compat family {identifier}: "
                  + ("admitted" if result["admitted"] else f"{gap['reason']}: {gap.get('detail', gap.get('status'))}"))
        require(assessment["family_complete"] is True, "c-abi-compat family remains incomplete; see retained gaps")
        print("c-abi-compat family evidence is complete; promotion remains independent")
    except (CAbiCompatFamilyError, cohort.CAbiCompatFamilyCohortError, family.ExecutionError) as error:
        parser.exit(1, f"owned c-abi-compat family: {error}\n")
    return 0


def _checkout_path(value: Path) -> Path:
    """Reduce a public path argument to its checkout-relative form."""

    if value.is_absolute():
        try:
            return value.relative_to(ROOT)
        except ValueError as error:
            raise CAbiCompatFamilyError(f"path escapes the checkout: {value}") from error
    return value


if __name__ == "__main__":
    raise SystemExit(main())
