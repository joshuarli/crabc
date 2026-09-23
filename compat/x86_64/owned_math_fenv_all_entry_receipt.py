#!/usr/bin/env python3
"""Collect three bounded math/fenv product-pair reports into one 18-cell receipt.

Each supplied runner report already contains its six ordinary execution cells:
static, static-PIE, and dynamic PIE/non-PIE through both kernel and direct
loader entry.  This adapter only retains and rechecks three such product pairs.
It does not publish a runtime, complete a family, or infer broader math scope.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

import owned_math_fenv_all_entry_contract as contract
import owned_math_fenv_all_entry_evidence as providers
import owned_crypt_runtime_evidence as payload_evidence
import owned_posix_family_execution as family
import owned_posix_product_evidence as product_evidence
import validate_owned_math_fenv_all_entry as stream

SCHEMA = "crabc.x86_64-owned-math-fenv-all-entry-receipt/v1"
REPORT_SCHEMA = "crabc.x86_64-owned-math-fenv-all-entry/v1"
PAIR_NAMES = tuple(family.PAIRS)
SCOPE = [
    "math.elementary-long-double", "math.elementary-fenv-sensitive",
    "math.special", "math.complex",
]
LINKAGES = ("static", "static-pie", "dynamic-pie", "dynamic-non-pie")
EXECUTION_CELLS = (
    ("static", "static-run"),
    ("static-pie", "static-pie-run"),
    ("dynamic-pie-kernel", "dynamic-pie-kernel"),
    ("dynamic-pie-direct", "dynamic-pie-direct"),
    ("dynamic-non-pie-kernel", "dynamic-non-pie-kernel"),
    ("dynamic-non-pie-direct", "dynamic-non-pie-direct"),
)
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
RUNNER = Path("compat/x86_64/run_owned_math_fenv_all_entry.sh")
VALIDATOR = Path("compat/x86_64/validate_owned_math_fenv_all_entry.py")
PROVIDER = Path("compat/x86_64/owned_math_fenv_all_entry_evidence.py")
COPIES = Path("compat/x86_64/owned_crypt_runtime_evidence.py")
CONTRACT = Path("compat/x86_64/owned_math_fenv_all_entry_contract.py")
COVERAGE = Path("compat/crabc-rs/coverage.toml")
COMPLEX_BASELINE = Path("compat/x86_64/validate_parity_ledger.py")
DRIVER = Path("compat/x86_64/owned_math_fenv_all_entry_driver.c")


def direct_sources() -> tuple[Path, ...]:
    return (
        *(Path(relative) for _role, relative, _define in contract.OBJECT_ROLES),
        RUNNER, VALIDATOR, CONTRACT, PROVIDER, COPIES, COVERAGE, COMPLEX_BASELINE,
    )


def expected_command_stems() -> set[str]:
    result = {"combine", "workload-imports", "dynamic-provider-symbols",
              "static-provider-symbols", "component-preflight", "component-collector",
              "oracle-link", "oracle-run"}
    for role, _relative, _define in contract.OBJECT_ROLES:
        result.update({f"header-{role}", f"compile-{role}"})
    for mode in ("static", "static-pie"):
        result.update({f"{mode}-link", f"{mode}-validate", f"{mode}-run"})
    for mode in ("pie", "non-pie"):
        prefix = f"dynamic-{mode}"
        result.update({f"{prefix}-link", f"{prefix}-validate", f"{prefix}-copy-before",
                       f"{prefix}-copy-audit-before", f"{prefix}-kernel", f"{prefix}-direct",
                       f"{prefix}-copy-audit-after"})
    return result


class ReceiptError(ValueError):
    """A product report cannot participate in this retained receipt."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def physical(root: Path, name: str) -> Path:
    candidate = Path(name)
    require(not candidate.is_absolute() and ".." not in candidate.parts,
            "receipt identity path escapes the checkout")
    root = root.resolve(strict=True)
    path = root / candidate
    current = root
    try:
        for part in candidate.parts:
            current /= part
            require(not current.is_symlink(), "receipt identity traverses a symbolic link")
    except OSError as error:
        raise ReceiptError("receipt identity path is unreadable") from error
    require(path.is_relative_to(root), "receipt identity resolves outside checkout")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), "receipt identity is not a physical regular file")
    return path


def physical_directory(root: Path, name: str, label: str) -> Path:
    candidate = Path(name)
    require(not candidate.is_absolute() and ".." not in candidate.parts,
            f"{label} path escapes the checkout")
    root = root.resolve(strict=True)
    path = root / candidate
    current = root
    try:
        for part in candidate.parts:
            current /= part
            require(not current.is_symlink(), f"{label} traverses a symbolic link")
    except OSError as error:
        raise ReceiptError(f"{label} path is unreadable") from error
    require(path.is_relative_to(root) and path.is_dir() and not path.is_symlink(),
            f"{label} is not a physical checkout directory")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReceiptError(f"cannot read {path.name}") from error
    require(isinstance(value, dict), f"{path.name} is not a JSON object")
    return value


def validate_identity(root: Path, value: object, label: str) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{label} identity fields differ")
    name, expected, size = value["path"], value["sha256"], value["size"]
    require(isinstance(name, str) and isinstance(expected, str) and len(expected) == 64
            and isinstance(size, int) and size >= 0, f"{label} identity value differs")
    path = physical(root, name)
    require(path.stat().st_size == size and digest(path) == expected,
            f"{label} identity differs")
    return path


def expected_symbols(root: Path) -> list[str]:
    return list(providers.selected_symbols(root))


def source_identity(root: Path, path: Path) -> dict[str, object]:
    path = physical(root, path.relative_to(root))
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": family.digest(path),
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def product_identity(root: Path, product: Path, kind: str) -> dict[str, object]:
    product = physical_directory(root, product.relative_to(root).as_posix(), f"{kind} product")
    manifest, _files = (
        product_evidence._validate_static_product(product) if kind == "static"
        else product_evidence._validate_dynamic_product(product)
    )
    return {
        "path": product.relative_to(root).as_posix(),
        "manifest": family.file_identity(root, manifest),
        "tree": family.snapshot(product),
    }


def expected_source_product_seal(root: Path, static: Path, dynamic: Path) -> dict[str, object]:
    sources = {path.name: source_identity(root, root / path) for path in direct_sources()}
    require(len(sources) == len(direct_sources()), "math/fenv direct source basenames collide")
    return {"sources": sources, "dynamic": product_identity(root, dynamic, "dynamic"),
            "static": product_identity(root, static, "static")}


def tool_identity(path: Path) -> dict[str, object]:
    path = path.resolve(strict=True)
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), "math/fenv tool is not physical")
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def expected_tool_seal(static: Path, dynamic: Path) -> dict[str, object]:
    helper = dynamic / "share/crabc/crabc_cc_static.py"
    spec = importlib.util.spec_from_file_location("owned_math_fenv_all_entry_receipt_tools", helper)
    require(spec is not None and spec.loader is not None, "cannot load supplied compiler helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        return {
            "oracle": tool_identity(ORACLE_CC),
            "dynamic_driver": tool_identity(dynamic / "bin/crabc-cc-dynamic"),
            "compiler": tool_identity(Path(module.compiler())),
            "linker": tool_identity(Path(module.linker(dynamic))),
            "static_driver": tool_identity(static / "bin/crabc-cc"),
        }
    finally:
        sys.modules.pop(spec.name, None)


def replay_provider_observations(root: Path, work: Path, dynamic: Path,
                                 static: Path) -> dict[str, bytes]:
    """Read the three retained provider views from their current artifacts.

    The report's command identities and exact argv have already been checked
    before this point.  This replay deliberately reconstructs only those three
    fixed inspection commands; it never executes a retained argv.
    """

    try:
        workload = physical(root, (work / "workload.o").relative_to(root).as_posix())
        dynamic_libc = physical(root, (dynamic / "usr/lib/libc.so").relative_to(root).as_posix())
        static_libc = physical(root, (static / "usr/lib/libc.a").relative_to(root).as_posix())
    except ValueError as error:
        raise ReceiptError("provider artifact path escapes the checkout") from error
    commands = {
        "workload-imports": [
            "/usr/bin/nm", "--undefined-only", "--format=posix", str(workload),
        ],
        "dynamic-provider-symbols": [
            "/usr/bin/readelf", "--dyn-syms", "-W", str(dynamic_libc),
        ],
        "static-provider-symbols": [
            "/usr/bin/nm", "-A", "-g", "--defined-only", "--format=posix", str(static_libc),
        ],
    }
    observations: dict[str, bytes] = {}
    for label, command in commands.items():
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReceiptError(f"{label} provider replay could not inspect its artifact") from error
        require(completed.returncode == 0,
                f"{label} provider replay exited with status {completed.returncode}")
        require(completed.stderr == b"", f"{label} provider replay wrote stderr")
        observations[label] = completed.stdout
    return observations


def validate_provider_record(root: Path, identity: object, command_paths: dict[str, dict[str, Path]],
                             work: Path, dynamic: Path, static: Path) -> Path:
    path = validate_identity(root, identity, "provider evidence")
    record = read(path)
    retained = {
        label: command_paths[label]["stdout"].read_bytes()
        for label in ("workload-imports", "dynamic-provider-symbols", "static-provider-symbols")
    }
    replayed = replay_provider_observations(root, work, dynamic, static)
    for label, output in replayed.items():
        require(retained[label] == output, f"{label} retained provider output differs from its artifact")
    try:
        imports = replayed["workload-imports"].decode("utf-8")
        dynamic_definitions = replayed["dynamic-provider-symbols"].decode("utf-8")
        static_definitions = replayed["static-provider-symbols"].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReceiptError("provider replay output is not UTF-8") from error
    observed = providers.validate(
        root,
        imports,
        dynamic_definitions,
        static_definitions,
        work,
        dynamic,
    )
    require(family.same_json(record, observed), "provider collector result differs")
    encoded = json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n"
    require(command_paths["component-preflight"]["stdout"].read_text(encoding="utf-8") == encoded
            and command_paths["component-collector"]["stdout"].read_text(encoding="utf-8") == encoded,
            "provider collector stdout differs")
    return path


def validate_command(root: Path, value: object, label: str) -> dict[str, Path]:
    require(isinstance(value, dict) and set(value) == {"argv", "stdout", "stderr", "status"},
            f"{label} command record differs")
    paths = {name: validate_identity(root, entry, f"{label} {name}")
             for name, entry in value.items()}
    require(paths["status"].read_bytes() == b"0\n", f"{label} did not exit successfully")
    return paths


def command_argv(paths: dict[str, Path], label: str) -> list[str]:
    try:
        value = json.loads(paths["argv"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} argv is unreadable") from error
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label} argv is not a string list")
    return value


def require_argv(paths: dict[str, Path], label: str, expected: list[str]) -> None:
    require(command_argv(paths, label) == expected, f"{label} argv differs")


def output_matches_oracle(paths: dict[str, Path], label: str, oracle: dict[str, Path]) -> None:
    try:
        stream.validate_bytes(paths["stdout"].read_bytes())
    except stream.ValidationError as error:
        raise ReceiptError(f"{label} math/fenv stream differs: {error}") from error
    require(paths["stdout"].read_bytes() == oracle["stdout"].read_bytes()
            and paths["stderr"].read_bytes() == oracle["stderr"].read_bytes()
            and paths["status"].read_bytes() == oracle["status"].read_bytes(),
            f"{label} raw result differs from the pinned musl oracle")


def validate_link(root: Path, paths: dict[str, dict[str, Path]], links: dict[str, object],
                  work: Path, static: Path, dynamic: Path, linkage: str) -> None:
    if linkage in {"static", "static-pie"}:
        product, executable, receipt = static, work / linkage, work / f"{linkage}.crabc-link.json"
        public_linkage = linkage
    else:
        mode = linkage.removeprefix("dynamic-")
        product, executable = dynamic, work / f"dynamic-{mode}"
        receipt = Path(str(executable) + ".crabc-link.json")
        public_linkage = mode
    link_record = validate_identity(root, links[linkage], f"{linkage} link")
    expected_record = product_evidence.validate_link(
        product, work / "workload.o", executable, receipt, public_linkage
    )
    require(family.same_json(read(link_record), expected_record), f"{linkage} public link evidence differs")
    encoded = json.dumps(expected_record, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        validate_stdout = paths[f"{linkage}-validate"]["stdout"].read_text(encoding="utf-8")
    except (KeyError, OSError) as error:
        raise ReceiptError(f"{linkage} retained link validation stdout is unavailable") from error
    require(validate_stdout == encoded, f"{linkage} retained link validation stdout differs")


def payload_arguments(action: str, root: Path, dynamic: Path, execution_root: Path,
                      executable: Path, record: Path) -> list[str]:
    return [
        "python3", "-B", str(root / COPIES), action, "--product", str(dynamic),
        "--execution-root", str(execution_root), "--source-consumer", str(executable),
        "--execution-consumer", str(execution_root / "consumer"), "--record", str(record),
    ]


def validate_dynamic_payload(root: Path, paths: dict[str, dict[str, Path]], payloads: dict[str, object],
                             work: Path, dynamic: Path, mode: str) -> None:
    prefix = f"dynamic-{mode}"
    item = payloads[mode]
    require(isinstance(item, dict) and set(item) == {"record", "before", "after"},
            f"{mode} dynamic payload record differs")
    recorded = validate_identity(root, item["record"], f"{mode} dynamic payload record")
    before = validate_identity(root, item["before"], f"{mode} dynamic payload before")
    after = validate_identity(root, item["after"], f"{mode} dynamic payload after")
    execution_root = work / f"dynamic-{mode}-root"
    executable = work / prefix
    expected_audit = payload_evidence.audit_execution_payload(
        dynamic, execution_root, executable, execution_root / "consumer", recorded,
    )
    encoded = json.dumps(expected_audit, sort_keys=True, separators=(",", ":")) + "\n"
    require(before.read_text(encoding="utf-8") == encoded and after.read_text(encoding="utf-8") == encoded,
            f"{mode} dynamic payload audit differs")
    require_argv(paths[f"{prefix}-copy-before"], f"{prefix} copy record",
                 payload_arguments("record", root, dynamic, execution_root, executable, recorded))
    expected_audit_argv = payload_arguments("audit", root, dynamic, execution_root, executable, recorded)
    require_argv(paths[f"{prefix}-copy-audit-before"], f"{prefix} copy audit before", expected_audit_argv)
    require_argv(paths[f"{prefix}-copy-audit-after"], f"{prefix} copy audit after", expected_audit_argv)


def validate_execution_commands(root: Path, paths: dict[str, dict[str, Path]], work: Path,
                                static: Path, dynamic: Path, tools: dict[str, object]) -> None:
    dynamic_driver = str(dynamic / "bin/crabc-cc-dynamic")
    static_driver = str(static / "bin/crabc-cc")
    linker = tools.get("linker")
    require(isinstance(linker, dict) and isinstance(linker.get("path"), str), "tool seal lacks linker")
    objects = [str(work / f"{role}.o") for role, _relative, _define in contract.OBJECT_ROLES]
    require_argv(paths["combine"], "combine", [str(linker["path"]), "-r", "-o", str(work / "workload.o"), *objects])
    require_argv(paths["workload-imports"], "workload imports",
                 ["nm", "--undefined-only", "--format=posix", str(work / "workload.o")])
    require_argv(paths["dynamic-provider-symbols"], "dynamic provider symbols",
                 ["readelf", "--dyn-syms", "-W", str(dynamic / "usr/lib/libc.so")])
    require_argv(paths["static-provider-symbols"], "static provider symbols",
                 ["nm", "-A", "-g", "--defined-only", "--format=posix", str(static / "usr/lib/libc.a")])
    provider_argv = [
        "python3", "-B", str(root / PROVIDER), "--root", str(root), "--work", str(work),
        "--dynamic-product", str(dynamic), "--imports", str(paths["workload-imports"]["stdout"]),
        "--dynamic-definitions", str(paths["dynamic-provider-symbols"]["stdout"]),
        "--static-definitions", str(paths["static-provider-symbols"]["stdout"]),
    ]
    require_argv(paths["component-preflight"], "component preflight", provider_argv)
    require_argv(paths["component-collector"], "component collector", provider_argv)
    require_argv(paths["oracle-link"], "oracle link", [
        str(ORACLE_CC), "-std=c11", "-static", "-fno-pie", "-no-pie", str(work / "workload.o"),
        "-lm", "-o", str(work / "oracle"),
    ])
    oracle_run = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(work / "oracle")]
    require_argv(paths["oracle-run"], "oracle run", oracle_run)
    for linkage in ("static", "static-pie"):
        receipt = work / f"{linkage}.crabc-link.json"
        require_argv(paths[f"{linkage}-link"], f"{linkage} link", [
            static_driver, f"-{linkage}", "--link-receipt", receipt.name,
            str(work / "workload.o"), "-o", str(work / linkage),
        ])
        require_argv(paths[f"{linkage}-validate"], f"{linkage} validate", [
            "python3", "-B", "-", str(root), str(static), str(work / "workload.o"),
            str(work / linkage), str(receipt), linkage,
        ])
        require_argv(paths[f"{linkage}-run"], f"{linkage} run",
                     ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(work / linkage)])
    for mode in ("pie", "non-pie"):
        prefix = f"dynamic-{mode}"
        executable = work / prefix
        receipt = Path(str(executable) + ".crabc-link.json")
        require_argv(paths[f"{prefix}-link"], f"{prefix} link",
                     [dynamic_driver, f"--dynamic-{mode}", str(work / "workload.o"), "-o", str(executable)])
        require_argv(paths[f"{prefix}-validate"], f"{prefix} validate", [
            "python3", "-B", "-", str(root), str(dynamic), str(work / "workload.o"),
            str(executable), str(receipt), mode,
        ])
        execution_root = work / f"dynamic-{mode}-root"
        require_argv(paths[f"{prefix}-kernel"], f"{prefix} kernel",
                     ["chroot", str(execution_root), "/consumer"])
        require_argv(paths[f"{prefix}-direct"], f"{prefix} direct",
                     ["chroot", str(execution_root), INTERPRETER, "/consumer"])


def validate_report(root: Path, path: Path, expected_products: dict[str, Path]) -> tuple[dict[str, Any], dict[str, bytes]]:
    report = read(path)
    required = {
        "schema", "scope", "source_objects", "products", "seals", "provider_evidence",
        "commands", "links", "execution_payloads", "family_completion", "promotion_ready",
        "public_support",
    }
    require(set(report) == required, "math/fenv runner report fields differ")
    require(report["schema"] == REPORT_SCHEMA and report["scope"] == SCOPE,
            "math/fenv runner report scope differs")
    require(report["family_completion"] is False and report["promotion_ready"] is False
            and report["public_support"] is False, "math/fenv report overclaims completion")
    work = path.parent
    require(path.name == "owned-math-fenv-all-entry.json", "math/fenv report filename differs")
    products = report["products"]
    require(isinstance(products, dict) and set(products) == {"static", "dynamic"}
            and all(isinstance(value, str) and value for value in products.values()),
            "math/fenv report lacks a supplied static/dynamic pair")
    static, dynamic = expected_products["static"], expected_products["dynamic"]
    require(products == {"static": static.relative_to(root).as_posix(),
                         "dynamic": dynamic.relative_to(root).as_posix()},
            "math/fenv report does not use its named prepared/qualified product pair")
    role_names = {role for role, _relative, _define in contract.OBJECT_ROLES} | {"workload"}
    objects = report["source_objects"]
    require(isinstance(objects, dict) and set(objects) == role_names,
            "math/fenv source object roster differs")
    object_paths = {}
    for name, value in objects.items():
        observed = validate_identity(root, value, f"source object {name}")
        require(observed == work / f"{name}.o", f"source object {name} path differs")
        object_paths[name] = observed
    seals = report["seals"]
    require(isinstance(seals, dict) and set(seals) == {
        "source-product-before", "source-product-after", "tools-before", "tools-after",
    }, "math/fenv seals differ")
    resolved_seals = {name: validate_identity(root, value, f"seal {name}")
                      for name, value in seals.items()}
    expected_source_seal = expected_source_product_seal(root, static, dynamic)
    require(family.same_json(read(resolved_seals["source-product-before"]), expected_source_seal)
            and family.same_json(read(resolved_seals["source-product-after"]), expected_source_seal),
            "source/product seal differs")
    expected_tools = expected_tool_seal(static, dynamic)
    require(family.same_json(read(resolved_seals["tools-before"]), expected_tools)
            and family.same_json(read(resolved_seals["tools-after"]), expected_tools),
            "tool seal differs")
    commands = report["commands"]
    needed_commands = {stem for _cell, stem in EXECUTION_CELLS}
    require(isinstance(commands, dict) and set(commands) == expected_command_stems()
            and needed_commands.issubset(commands), "math/fenv command roster differs")
    command_paths = {name: validate_command(root, value, name) for name, value in commands.items()}
    validate_execution_commands(root, command_paths, work, static, dynamic, expected_tools)
    validate_provider_record(root, report["provider_evidence"], command_paths, work, dynamic, static)
    links = report["links"]
    require(isinstance(links, dict) and set(links) == set(LINKAGES),
            "math/fenv retained product link roster differs")
    for linkage in LINKAGES:
        validate_link(root, command_paths, links, work, static, dynamic, linkage)
    payloads = report["execution_payloads"]
    require(isinstance(payloads, dict) and set(payloads) == {"pie", "non-pie"},
            "math/fenv dynamic payload roster differs")
    for mode in ("pie", "non-pie"):
        validate_dynamic_payload(root, command_paths, payloads, work, dynamic, mode)
    oracle = command_paths["oracle-run"]
    try:
        stream.validate_bytes(oracle["stdout"].read_bytes())
    except stream.ValidationError as error:
        raise ReceiptError(f"pinned musl oracle math/fenv stream differs: {error}") from error
    require(not oracle["stderr"].read_bytes(), "pinned musl oracle emitted stderr")
    for _cell, stem in EXECUTION_CELLS:
        output_matches_oracle(command_paths[stem], stem, oracle)
    return report, {name: object_paths[name].read_bytes()
                    for name, _relative, _define in contract.OBJECT_ROLES}


def collect(root: Path, static_preparation: Path, dynamic_qualification: Path,
            reports: dict[str, Path]) -> dict[str, Any]:
    require(set(reports) == set(PAIR_NAMES), "receipt requires primary, reproduction, and extracted reports")
    root = root.resolve(strict=True)
    request = {
        "schema": family.SCHEMA, "source_mount": str(root),
        "static_preparation": static_preparation.as_posix(),
        "dynamic_qualification": dynamic_qualification.as_posix(),
    }
    inputs, products = family.input_products(root, request)
    pairs = {}
    report_paths: set[Path] = set()
    product_pairs: set[tuple[Path, Path]] = set()
    canonical_objects: dict[str, bytes] | None = None
    for name in PAIR_NAMES:
        path = physical(root, reports[name].as_posix())
        require(path not in report_paths, "receipt reuses a product-pair report")
        report_paths.add(path)
        _report, objects = validate_report(root, path, products[name])
        product_pair = (products[name]["static"], products[name]["dynamic"])
        require(product_pair not in product_pairs, "receipt reuses a static/dynamic product pair")
        product_pairs.add(product_pair)
        if canonical_objects is None:
            canonical_objects = objects
        else:
            require(objects == canonical_objects, "math/fenv object bytes differ across product pairs")
        pairs[name] = {
            "report": path.relative_to(root).as_posix(),
            "report_sha256": digest(path),
            "cells": [cell for cell, _stem in EXECUTION_CELLS],
        }
    return {
        "schema": SCHEMA,
        "scope": SCOPE,
        "inputs": inputs,
        "pairs": pairs,
        "cell_count": len(PAIR_NAMES) * len(EXECUTION_CELLS),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }


def parse_report(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or name not in PAIR_NAMES or not path:
        raise argparse.ArgumentTypeError("report must be NAME=CHECKOUT_RELATIVE_PATH")
    return name, Path(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--static-preparation", type=Path, required=True)
    parser.add_argument("--dynamic-qualification", type=Path, required=True)
    parser.add_argument("--report", type=parse_report, action="append", required=True)
    arguments = parser.parse_args()
    reports = dict(arguments.report)
    if len(reports) != len(arguments.report):
        parser.error("each report name may appear once")
    try:
        print(json.dumps(collect(arguments.root, arguments.static_preparation,
                                 arguments.dynamic_qualification, reports),
                         sort_keys=True, separators=(",", ":")))
    except (OSError, ReceiptError, contract.ContractError, providers.EvidenceError,
            family.ExecutionError, product_evidence.ProductEvidenceError,
            payload_evidence.CryptRuntimeEvidenceError) as error:
        print(f"owned math/fenv receipt: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
