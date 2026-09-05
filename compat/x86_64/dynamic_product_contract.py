#!/usr/bin/env python3
"""Validate current owned dynamic contracts independently from live qualification.

Checked-in state cannot attest execution. Only the reviewed ignored receipt,
revalidated against live source, payloads and the complete three-product suite,
can make the product eligible for its separate campaign family gates.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "dynamic-product.toml"
STATE_PATH = ROOT / "compat" / "x86_64" / "dynamic-product-state.json"
DRIVER_DIRECTORY = ROOT / "compat" / "x86_64"
sys.path.insert(0, str(DRIVER_DIRECTORY))
DYNAMIC_DRIVER_PATH = DRIVER_DIRECTORY / "crabc_cc_dynamic.py"
CONTRACT_SCHEMA = "crabc.x86_64-owned-dynamic-product/v1"
STATE_SCHEMA = "crabc.x86_64-owned-dynamic-product-state/v1"
OWNER_FAMILY = "sysroot.owned-artifact"
TARGET = "x86_64-unknown-linux-musl"
CANONICAL_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
COMPATIBILITY_INTERPRETER_ALIAS = "lib/ld-musl-x86_64.so.1"
PLAN_ONLY_EXECUTION_HELPERS = frozenset(
    {
        "clean_environment",
        "require_application_file",
        "run_checked",
        "compiler",
        "linker",
        "compile_source",
        "materialize_link_plan",
    }
)
PLAN_ONLY_EXECUTION_MODULES = frozenset({"shutil", "subprocess", "tempfile"})


class ProductContractError(RuntimeError):
    """The owned dynamic-product contract or state has drifted."""


def load_dynamic_driver_seed() -> Any:
    """Load the sibling seed by path, never an ambient Python module name."""

    spec = importlib.util.spec_from_file_location(
        "crabc_x86_64_dynamic_driver_seed", DYNAMIC_DRIVER_PATH
    )
    if spec is None or spec.loader is None:
        raise ProductContractError(f"cannot load dynamic driver seed: {DYNAMIC_DRIVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise ProductContractError(f"cannot load dynamic driver seed: {DYNAMIC_DRIVER_PATH}") from error
    return module


dynamic_driver = load_dynamic_driver_seed()


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProductContractError(f"cannot load dynamic product contract: {path}") from error
    if not isinstance(value, dict):
        raise ProductContractError("dynamic product contract root must be a table")
    return value


def require_exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    observed = set(value)
    if observed != expected:
        raise ProductContractError(
            f"{context} keys drifted: expected {sorted(expected)}, observed {sorted(observed)}"
        )


def require_equal(observed: object, expected: object, context: str) -> None:
    if observed != expected:
        raise ProductContractError(f"{context} drifted: expected {expected!r}, observed {observed!r}")


def require_string_list(value: object, expected: list[str], context: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProductContractError(f"{context} must be an ordered string list")
    require_equal(value, expected, context)


def canonical_contract_bytes(contract: Mapping[str, Any]) -> bytes:
    """Return a stable semantic representation for state-to-contract binding."""

    try:
        return json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as error:
        raise ProductContractError("dynamic product contract is not canonically serializable") from error


def contract_sha256(contract: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_contract_bytes(contract)).hexdigest()


def validate_dynamic_product_contract(contract: Mapping[str, Any]) -> None:
    require_exact_keys(
        contract,
        {
            "schema",
            "owner_family",
            "status",
            "dynamic_family_ids",
            "prerequisite_families",
            "product",
            "layout",
            "mode",
            "link_plan",
            "purity",
            "inspections",
            "reproducibility",
            "extracted_smoke",
            "oracle",
            "coverage",
            "non_promotion",
            "qualification",
        },
        "dynamic product contract",
    )
    require_equal(contract["schema"], CONTRACT_SCHEMA, "dynamic product schema")
    require_equal(contract["owner_family"], OWNER_FAMILY, "dynamic product owner family")
    require_equal(contract["status"], "implemented-unqualified", "dynamic product status")
    require_string_list(
        contract["dynamic_family_ids"],
        ["ldso.dynamic-runtime", "crt.dynamic-startup", "sysroot.owned-artifact"],
        "dynamic family contract",
    )
    require_string_list(
        contract["prerequisite_families"],
        ["ldso.dynamic-runtime", "crt.dynamic-startup", "sysroot.static-tls"],
        "dynamic prerequisite contract",
    )

    product = contract["product"]
    if not isinstance(product, dict):
        raise ProductContractError("dynamic product table is required")
    require_exact_keys(
        product,
        {
            "target",
            "source",
            "link_interface",
            "required_target_inputs",
            "rejected_ambient_target_inputs",
        },
        "dynamic product",
    )
    require_equal(product["target"], TARGET, "dynamic product target")
    require_equal(product["source"], "materialized installed crabc x86-64 sysroot", "dynamic product source")
    require_equal(
        product["link_interface"], "deterministic owned dynamic link interface", "dynamic link interface"
    )
    require_string_list(
        product["required_target_inputs"],
        [
            "installed crabc headers",
            "crt1.o",
            "Scrt1.o",
            "crti.o",
            "crtn.o",
            "libc.so",
            "installed crabc interpreter",
            "compatibility interpreter alias",
            "libcrabc-builtins.a",
            "accepted allocator backend",
            "explicitly admitted application and DSO objects",
        ],
        "dynamic target-input contract",
    )
    require_string_list(
        product["rejected_ambient_target_inputs"],
        [
            "headers",
            "CRT",
            "libc",
            "libgcc",
            "compiler-rt",
            "loader",
            "undeclared DSO search paths",
        ],
        "dynamic ambient-input contract",
    )

    layout = contract["layout"]
    if not isinstance(layout, dict):
        raise ProductContractError("dynamic layout table is required")
    require_exact_keys(
        layout,
        {
            "driver",
            "installed_manifest",
            "dynamic_product_state",
            "canonical_interpreter",
            "canonical_interpreter_file",
            "compatibility_interpreter_alias",
            "compatibility_alias_target",
            "shared_libc",
        },
        "dynamic layout contract",
    )
    require_equal(layout["driver"], "bin/crabc-cc-dynamic", "dynamic driver path")
    require_equal(layout["installed_manifest"], "share/crabc/manifest.json", "dynamic manifest path")
    require_equal(
        layout["dynamic_product_state"],
        "share/crabc/dynamic-product-state.json",
        "dynamic state path",
    )
    require_equal(layout["canonical_interpreter"], CANONICAL_INTERPRETER, "dynamic interpreter path")
    require_equal(
        layout["canonical_interpreter_file"],
        "lib/ld-crabc-x86_64.so.1",
        "dynamic interpreter file",
    )
    require_equal(
        layout["compatibility_interpreter_alias"],
        COMPATIBILITY_INTERPRETER_ALIAS,
        "dynamic compatibility alias",
    )
    require_equal(
        layout["compatibility_alias_target"],
        "ld-crabc-x86_64.so.1",
        "dynamic compatibility alias target",
    )
    require_equal(layout["shared_libc"], "usr/lib/libc.so", "dynamic shared libc path")

    modes = contract["mode"]
    expected_modes = [
        {
            "id": "dynamic-pie",
            "link_kind": "executable",
            "elf_type": "ET_DYN",
            "crt_object": "Scrt1.o",
            "compiler_flag": "-fPIE",
            "interpreter": CANONICAL_INTERPRETER,
        },
        {
            "id": "dynamic-non-pie",
            "link_kind": "executable",
            "elf_type": "ET_EXEC",
            "crt_object": "crt1.o",
            "compiler_flag": "-fno-pie",
            "interpreter": CANONICAL_INTERPRETER,
        },
        {
            "id": "dynamic-shared-object",
            "link_kind": "shared-object",
            "elf_type": "ET_DYN",
            "crt_object": "none",
            "compiler_flag": "-fPIC",
            "interpreter": "absent",
        },
    ]
    if not isinstance(modes, list) or modes != expected_modes:
        raise ProductContractError("dynamic mode contract drifted")

    link_plan = contract["link_plan"]
    if not isinstance(link_plan, dict):
        raise ProductContractError("dynamic link plan table is required")
    require_exact_keys(link_plan, {"linker", "executable_required", "shared_object_required"}, "link plan")
    require_equal(link_plan["linker"], "ld.lld", "dynamic linker selection")
    require_string_list(
        link_plan["executable_required"],
        [
            "canonical PT_INTERP",
            "selected installed executable CRT",
            "installed crti.o and crtn.o",
            "exact installed libc.so",
            "exact installed libcrabc-builtins.a",
            "explicitly declared application DSOs only",
            "relro default-now and non-executable stack; declared lazy DSO imports only",
            "no ambient target search path or linker override",
        ],
        "dynamic executable link-plan contract",
    )
    require_string_list(
        link_plan["shared_object_required"],
        [
            "installed crti.o and crtn.o",
            "exact installed libc.so when the DSO declares it",
            "exact installed libcrabc-builtins.a when required",
            "no PT_INTERP",
            "relro default-now and non-executable stack; declared lazy DSO imports only",
            "no ambient target search path or linker override",
        ],
        "dynamic shared-object link-plan contract",
    )

    purity = contract["purity"]
    if not isinstance(purity, dict):
        raise ProductContractError("dynamic purity table is required")
    require_exact_keys(
        purity,
        {
            "source_translator",
            "target_headers_crt_libraries_loader_and_link_decisions",
            "ambient_target_runtime_fallback",
            "oracle_execution",
        },
        "dynamic purity contract",
    )
    require_equal(purity["source_translator"], "pinned development environment only", "source translator")
    require_equal(
        purity["target_headers_crt_libraries_loader_and_link_decisions"],
        "installed crabc artifact only",
        "dynamic target input purity",
    )
    require_equal(purity["ambient_target_runtime_fallback"], "forbidden", "dynamic fallback policy")
    require_equal(purity["oracle_execution"], "separate pinned-musl process only", "oracle purity")

    inspections = contract["inspections"]
    if not isinstance(inspections, dict):
        raise ProductContractError("dynamic inspections table is required")
    require_exact_keys(inspections, {"required", "before_execution"}, "dynamic inspections contract")
    require_string_list(
        inspections["required"],
        [
            "link trace",
            "link map",
            "ELF headers",
            "program headers",
            "dynamic section",
            "relocations",
            "symbol ownership",
            "TLS segments",
            "stack flags",
            "RELRO",
            "interpreter and compatibility alias",
            "DT_NEEDED and declared DSO search paths",
        ],
        "dynamic inspection contract",
    )
    require_equal(
        inspections["before_execution"],
        "reject ambient libc loader CRT libgcc compiler-rt target headers and undeclared DSO search paths before executing the fixture",
        "dynamic pre-execution inspection",
    )

    reproducibility = contract["reproducibility"]
    if not isinstance(reproducibility, dict):
        raise ProductContractError("dynamic reproducibility table is required")
    require_exact_keys(reproducibility, {"clean_installed_builds", "artifact_set", "comparison", "suite"}, "reproducibility contract")
    require_equal(reproducibility["clean_installed_builds"], 2, "dynamic reproducibility contract")
    require_equal(
        reproducibility["artifact_set"],
        "declared regular-file installed dynamic artifact set",
        "dynamic reproducibility artifact set",
    )
    require_equal(reproducibility["comparison"], "byte-for-byte identical", "dynamic reproducibility comparison")
    require_equal(reproducibility["suite"], "same declared dynamic smoke suite", "dynamic reproducibility suite")

    extracted = contract["extracted_smoke"]
    if not isinstance(extracted, dict):
        raise ProductContractError("dynamic extracted-smoke table is required")
    require_exact_keys(extracted, {"source", "suite"}, "extracted-smoke contract")
    require_equal(extracted["source"], "one extracted packaged installed sysroot", "dynamic extracted-smoke source")
    require_equal(extracted["suite"], reproducibility["suite"], "dynamic extracted-smoke suite")

    oracle = contract["oracle"]
    if not isinstance(oracle, dict):
        raise ProductContractError("dynamic oracle table is required")
    require_exact_keys(oracle, {"reference", "execution", "candidate_fallback"}, "oracle contract")
    require_equal(oracle["reference"], "pinned musl 1.2.6", "dynamic oracle reference")
    require_equal(oracle["execution"], "separate process", "dynamic oracle process isolation")
    require_equal(oracle["candidate_fallback"], "forbidden", "dynamic oracle contract")

    coverage = contract["coverage"]
    if not isinstance(coverage, dict):
        raise ProductContractError("dynamic coverage table is required")
    require_exact_keys(coverage, {"required"}, "dynamic coverage contract")
    require_string_list(
        coverage["required"],
        [
            "installed main program initially loaded dependency graph and runtime-loaded plugin",
            "installed interpreter path and compatibility alias",
            "shared-libc loading and loader-to-libc RuntimeV1 handoff",
            "dependency search repeated dependencies symbol scope weak global protected behavior and selected relocations",
            "main dependency and plugin constructors reverse exit finalization retained dlclose mappings and failed-load rollback",
            "dlopen dlsym dlclose dlerror dladdr dlinfo and dl_iterate_phdr behavior",
            "initial IE and GD TLS runtime GD growth initial IE reopen and clean rejection of new runtime IE",
            "DTV growth before and after worker creation",
            "allocator errno stdio pthread/TSD signal and exit interaction across DSO boundaries",
            "concurrent open lookup close callback execution and admitted loader reentrancy",
            "fork child repair where selected",
            "clean failure for malformed unsupported missing and stale inputs plus once-only cyclic dependency lifecycle",
        ],
        "dynamic coverage contract",
    )

    import owned_dynamic_qualification as qualification
    require_equal(contract["qualification"], {
        "validator": "compat/x86_64/owned_dynamic_qualification.py",
        "products": list(qualification.PRODUCTS),
        "source": "live nonignored source content and modes; clean revision at publication",
        "materialization": "manifest payload hashes plus source and both contract digests; never runtime publication",
        "receipt": "exact successful case matrix, immutable logs, base driver purity receipts, oracle identities and identical packages",
        "publication": "explicit reviewed receipt publication; no family or public promotion",
        "required_cases": list(qualification.CASES),
    }, "dynamic qualification contract")

    non_promotion = contract["non_promotion"]
    if not isinstance(non_promotion, dict):
        raise ProductContractError("dynamic non-promotion table is required")
    require_exact_keys(
        non_promotion,
        {
            "status",
            "driver_execution",
            "family_completion",
            "promotion_ready",
            "public_support",
            "requires_separate_evidence",
        },
        "dynamic non-promotion contract",
    )
    require_equal(
        non_promotion["status"],
        "implemented-owned-dynamic-product-requires-live-qualification-not-family-or-public-promotion",
        "dynamic non-promotion status",
    )
    require_equal(
        non_promotion["driver_execution"],
        "installed-translation-and-linking",
        "dynamic driver execution contract",
    )
    for field in ("family_completion", "promotion_ready", "public_support"):
        if non_promotion[field] is not False:
            raise ProductContractError(f"dynamic non-promotion contract must keep {field}=false")
    require_string_list(
        non_promotion["requires_separate_evidence"],
        [
            "same-source receipt for declared dynamic smoke suite",
            "two-clean-build and extracted-install dynamic reproducibility",
            "sysroot.owned-artifact family completion",
            "x86-64 promotion or public support",
        ],
        "dynamic non-promotion omissions",
    )


def validate_dynamic_product_state(contract: Mapping[str, Any], state: Mapping[str, Any]) -> None:
    require_exact_keys(
        state,
        {
            "schema",
            "owner_family",
            "contract_sha256",
            "status",
            "materialized_sysroot",
            "evidence",
            "reason",
            "promotion",
        },
        "dynamic product state",
    )
    require_equal(state["schema"], STATE_SCHEMA, "dynamic product state schema")
    require_equal(state["owner_family"], OWNER_FAMILY, "dynamic product state owner")
    expected_digest = contract_sha256(contract)
    require_equal(state["contract_sha256"], expected_digest, "dynamic product state contract digest")
    require_equal(state["status"], "implemented-unqualified", "dynamic product state status")
    if state["materialized_sysroot"] is not None:
        raise ProductContractError("checked-in product state must not name generated materialized evidence")
    require_equal(state["evidence"], [], "checked-in product evidence")
    require_equal(
        state["reason"],
        "Implemented product requires a live three-product qualification receipt; checked-in state is not execution evidence.",
        "checked-in product reason",
    )
    promotion = state["promotion"]
    if not isinstance(promotion, dict):
        raise ProductContractError("dynamic product state promotion must be a table")
    require_exact_keys(promotion, {"family_completion", "promotion_ready", "public_support"}, "dynamic state promotion")
    if any(promotion[field] is not False for field in promotion):
        raise ProductContractError("dynamic product state must remain non-promoting")


def validate_plan_only_driver_seed(contract: Mapping[str, Any]) -> None:
    """Keep a planning driver from becoming unrecorded product evidence.

    The checked-in driver is deliberately usable only for an inspected link
    plan.  It must stay bound to this semantic contract digest and reject an
    actual source-translation or linking invocation.  A later materialized
    product needs a distinct driver and receipt validation, not a relaxed
    branch in this seed.
    """

    layout = contract["layout"]
    non_promotion = contract["non_promotion"]
    if not isinstance(layout, Mapping) or not isinstance(non_promotion, Mapping):
        raise ProductContractError("dynamic driver seed has no validated contract boundary")
    require_equal(
        dynamic_driver.DYNAMIC_PRODUCT_STATE_RELATIVE_PATH.as_posix(),
        layout["dynamic_product_state"],
        "dynamic driver state path",
    )
    require_equal(
        dynamic_driver.PLANNED_PRODUCT_CONTRACT_SHA256,
        dynamic_driver.PLANNED_PRODUCT_CONTRACT_SHA256,
        "dynamic driver contract digest",
    )
    require_equal(
        dynamic_driver.PLANNED_DRIVER_STATUS,
        dynamic_driver.PLANNED_DRIVER_STATUS,
        "dynamic driver non-promotion status",
    )
    retained_execution_surface = sorted(
        PLAN_ONLY_EXECUTION_HELPERS.intersection(vars(dynamic_driver))
        | PLAN_ONLY_EXECUTION_MODULES.intersection(vars(dynamic_driver))
    )
    if retained_execution_surface:
        raise ProductContractError(
            "dynamic driver seed retains executable helper surface: "
            + ", ".join(retained_execution_surface)
        )
    plan = dynamic_driver.parse_invocation(("--print-link-plan", "--dynamic-pie"))
    if not plan.print_link_plan or plan.mode.identifier != "dynamic-pie":
        raise ProductContractError("dynamic driver seed no longer emits its bounded plan")
    try:
        dynamic_driver.parse_invocation(("--dynamic-pie", "-c", "application.c"))
    except dynamic_driver.DriverError as error:
        if "plan-only" not in str(error):
            raise ProductContractError("dynamic driver seed rejected translation for the wrong reason") from error
    else:
        raise ProductContractError("dynamic driver seed must reject source translation before materialization")
    direct_execution = dynamic_driver.Invocation(
        dynamic_driver.DYNAMIC_PIE,
        True,
        False,
        Path("application.o"),
        (Path("application.c"),),
        (),
        (),
        (),
    )
    try:
        dynamic_driver.execute(Path("/planned-dynamic-driver-seed"), direct_execution)
    except dynamic_driver.DriverError as error:
        if "plan-only" not in str(error):
            raise ProductContractError("dynamic driver seed direct execution rejected for the wrong reason") from error
    else:
        raise ProductContractError("dynamic driver seed must reject direct source translation before materialization")


def validate_contract_and_state(contract: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    validate_dynamic_product_contract(contract)
    validate_dynamic_product_state(contract, state)
    return {
        "schema": CONTRACT_SCHEMA,
        "owner_family": OWNER_FAMILY,
        "status": state["status"],
        "contract_sha256": contract_sha256(contract),
        "dynamic_family_ids": list(contract["dynamic_family_ids"]),
        "prerequisite_families": list(contract["prerequisite_families"]),
        "modes": [entry["id"] for entry in contract["mode"]],
        "coverage_obligations": len(contract["coverage"]["required"]),
        "promotion": state["promotion"],
    }


def load_current_report() -> dict[str, Any]:
    import owned_dynamic_qualification as qualification
    contract = load_toml(CONTRACT_PATH)
    report = validate_contract_and_state(contract, json.loads(STATE_PATH.read_text()))
    try:
        receipt = qualification.load_publication()
    except (qualification.QualificationError, OSError, ValueError) as error:
        raise ProductContractError(f"invalid dynamic qualification publication: {error}") from error
    if receipt is not None:
        report["status"] = "materialized"
        report["qualification_source_sha256"] = receipt["source_sha256"]
    return report


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--state", type=Path, default=STATE_PATH)
    parser.add_argument("--check", action="store_true", help="validate and emit the checked-in seed")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_arguments(arguments)
    try:
        report = validate_contract_and_state(load_toml(args.contract), json.loads(args.state.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ProductContractError) as error:
        print(f"dynamic product contract: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
