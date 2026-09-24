#!/usr/bin/env python3
"""Reconstruct the bounded installed text/locale/numeric component.

The installed runner deliberately combines the ordinary probe callables in one
ET_REL workload and keeps the public-alias probe in a second ET_REL workload.
This reader makes that distinction durable: every retained command, object,
link receipt, copied dynamic payload, raw oracle stream, provider projection,
and selected alias table is tied back to a physical artifact before it can
credit one of the fixed contract rows.  It is a finite component receipt, not a
family completion or a claim about the separately owned stdio stream engine.
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
from typing import Any, Mapping

import locale_alias_contract_symbols as alias_symbols
import owned_crypt_runtime_evidence as payload_evidence
import owned_posix_family_execution as family
import owned_posix_product_evidence as product_evidence
import owned_posix_static_products as static_products
import owned_text_locale_numeric_component_contract as contract
import owned_text_locale_numeric_component_evidence as providers


ROOT = Path(__file__).resolve().parents[2]
SOURCE_MOUNT = "/workspace"
SCHEMA = "crabc.x86_64-owned-text-locale-numeric-receipt/v1"
REPORT_SCHEMA = "crabc.x86_64-owned-text-locale-numeric/v1"
PAIR_NAMES = tuple(family.PAIRS)
EXECUTION_CELLS = contract.EXECUTION_CELLS
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
RUNNER = Path("compat/x86_64/run_owned_text_locale_numeric_component.sh")
RECEIPT = Path("compat/x86_64/owned_text_locale_numeric_component_receipt.py")
PROVIDER = Path("compat/x86_64/owned_text_locale_numeric_component_evidence.py")
COPIES = Path("compat/x86_64/owned_crypt_runtime_evidence.py")
ALIAS_CONTRACT = Path("compat/x86_64/locale_alias_contract.json")
ALIAS_SYMBOLS = Path("compat/x86_64/locale_alias_contract_symbols.py")

# The aggregate has one source identity, one POSIX product boundary, three
# report roots, and exactly the contract's source-to-row records.  Keeping this
# literal list lets the family coordinator snapshot report roots without
# guessing that they live below the aggregate receipt's parent directory.
RECEIPT_FIELDS = (
    "schema", "source", "inputs", "products", "rows", "pair_evidence_roots",
    "pairs", "cell_count", "family_completion", "promotion_ready", "public_support",
)
REPORT_FIELDS = (
    "schema", "scope", "rows", "abi_contract", "source_objects", "products", "seals",
    "provider_evidence", "commands", "links", "execution_payloads", "source_object_checks",
    "source_specific_evidence", "execution_cells", "family_completion", "promotion_ready", "public_support",
)
WORKLOADS = ("normal", "alias")
SOURCE_SPECIFIC_WORKLOAD = "source-specific"
ALL_WORKLOADS = (*WORKLOADS, SOURCE_SPECIFIC_WORKLOAD)
LINKAGES = ("static", "static-pie", "dynamic-pie", "dynamic-non-pie")
SOURCE_SPECIFIC_EXECUTION_CELLS = contract.SOURCE_SPECIFIC_EXECUTION_CELLS
SOURCE_SPECIFIC_ORACLE_RELATION = "candidate-static-mode-consistency/no-musl-oracle"
SOURCE_SPECIFIC_UNCLOSED_GAPS = ()
NORMAL_FRAME_ROLES = (
    "float-parse", "ctype-locators", "locale-narrow", "locale-object-wide",
    "locale-wide-iconv", "locale-multibyte", "wide-character", "strfmon", "wide-conversion",
    "uchar-stateful", "c32rtomb", "wcswcs", "locale-error-strings", "text-locale-differential",
    "wide-stream-differential",
)
ALIAS_SYMBOL_STEMS = (
    "oracle-static-symbols", "oracle-dynamic-symbols", "oracle-shared-symbols",
    "candidate-static-symbols", "candidate-dynamic-symbols", "candidate-shared-symbols",
    "executable-dynamic-pie-symbols", "executable-dynamic-non-pie-symbols",
)


class ReceiptError(ValueError):
    """A report or aggregate no longer proves the fixed component contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("retained JSON repeats an object key")
        result[key] = value
    return result


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"cannot read {label}") from error


def physical_directory(root: Path, path: Path, label: str) -> Path:
    """Resolve one checkout-relative physical directory without symlink hops."""

    root = root.resolve(strict=True)
    require(not path.is_absolute() and path.parts and all(part not in {"", ".", ".."} for part in path.parts),
            f"{label} path escapes the checkout")
    candidate = root / path
    current = root
    try:
        for part in path.parts:
            current /= part
            metadata = current.lstat()
            require(not stat.S_ISLNK(metadata.st_mode), f"{label} traverses a symbolic link")
        metadata = candidate.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is absent") from error
    require(stat.S_ISDIR(metadata.st_mode), f"{label} is not a physical directory")
    return candidate


def physical_file(root: Path, path: Path, label: str) -> Path:
    """Resolve one checkout-relative physical regular file without symlink hops."""

    root = root.resolve(strict=True)
    require(not path.is_absolute() and path.parts and all(part not in {"", ".", ".."} for part in path.parts),
            f"{label} path escapes the checkout")
    candidate = root / path
    current = root
    try:
        for part in path.parts:
            current /= part
            metadata = current.lstat()
            require(not stat.S_ISLNK(metadata.st_mode), f"{label} traverses a symbolic link")
        metadata = candidate.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is absent") from error
    require(stat.S_ISREG(metadata.st_mode), f"{label} is not a physical regular file")
    return candidate


def relative(root: Path, path: Path, label: str) -> Path:
    root = root.resolve(strict=True)
    try:
        value = path.resolve(strict=False).relative_to(root)
    except ValueError as error:
        raise ReceiptError(f"{label} escapes the checkout") from error
    require(value.parts and all(part not in {"", ".", ".."} for part in value.parts),
            f"{label} lacks a checkout-relative path")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
    except OSError as error:
        raise ReceiptError(f"cannot hash {path}") from error
    return value.hexdigest()


def identity(root: Path, path: Path, label: str) -> dict[str, object]:
    path = physical_file(root, relative(root, path, label), label)
    return {"path": relative(root, path, label).as_posix(), "sha256": digest(path),
            "size": path.stat().st_size}


def assert_identity(root: Path, value: object, label: str, *, expected: Path | None = None) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{label} identity fields differ")
    name, expected_digest, expected_size = value["path"], value["sha256"], value["size"]
    require(isinstance(name, str) and isinstance(expected_digest, str) and len(expected_digest) == 64
            and type(expected_size) is int and expected_size >= 0, f"{label} identity is malformed")
    path = physical_file(root, Path(name), label)
    if expected is not None:
        require(path == physical_file(root, relative(root, expected, label), label), f"{label} path differs")
    require(identity(root, path, label) == value, f"{label} bytes differ")
    return path


def mounted(root: Path, path: Path) -> str:
    """Render a physical checkout path as the pinned container's stable mount."""

    try:
        return str(Path(SOURCE_MOUNT) / path.resolve(strict=False).relative_to(root.resolve(strict=True)))
    except ValueError:
        return str(path.resolve(strict=False))


def row_records() -> list[dict[str, object]]:
    return [{"capability": capability, "id": row, "roles": list(roles)}
            for capability, row, roles in contract.ROWS]


def source_specific_row_records() -> list[dict[str, object]]:
    """Return non-credit rows for macro-gated candidate source behavior."""

    return [
        {"id": row, "roles": list(roles), "comparison": comparison,
         "credit": False, "limitation": limitation}
        for row, roles, comparison, limitation in contract.SOURCE_SPECIFIC_ROWS
    ]


def object_path(work: Path, name: str) -> Path:
    if name == "normal-workload":
        return work / "normal-workload.o"
    return work / f"{name}.o"


def workload_object(work: Path, workload: str) -> Path:
    require(workload in ALL_WORKLOADS, "unknown workload")
    if workload == "normal":
        return work / "normal-workload.o"
    if workload == "alias":
        return work / f"{contract.ALIAS_ROLE}.o"
    return work / "source-specific-workload.o"


def executable_path(work: Path, workload: str, linkage: str) -> Path:
    require(workload in ALL_WORKLOADS and linkage in LINKAGES, "unknown workload linkage")
    return work / f"{workload}-{linkage}"


def link_receipt_path(work: Path, workload: str, linkage: str) -> Path:
    executable = executable_path(work, workload, linkage)
    if linkage in {"static", "static-pie"}:
        return work / f"{workload}-{linkage}.crabc-link.json"
    return Path(str(executable) + ".crabc-link.json")


def product_link_path(work: Path, workload: str, linkage: str) -> Path:
    return work / f"{workload}-{linkage}.product-link.json"


def source_identity(root: Path, path: Path) -> dict[str, object]:
    record = identity(root, path, "component source")
    record["mode"] = stat.S_IMODE(path.stat().st_mode)
    return record


def product_identity(root: Path, product: Path, kind: str) -> dict[str, object]:
    product = physical_directory(root, relative(root, product, f"{kind} product"), f"{kind} product")
    try:
        manifest, _files = (product_evidence._validate_static_product(product) if kind == "static"
                            else product_evidence._validate_dynamic_product(product))
    except product_evidence.ProductEvidenceError as error:
        raise ReceiptError(f"{kind} product validation failed") from error
    return {"path": relative(root, product, f"{kind} product").as_posix(),
            "manifest": identity(root, manifest, f"{kind} manifest"), "tree": family.snapshot(product)}


def source_product_seal(root: Path, static: Path, dynamic: Path) -> dict[str, object]:
    """Seal the finite component sources and both supplied product trees."""

    sources: dict[str, dict[str, object]] = {}
    for source in contract.direct_sources():
        name = source.as_posix()
        require(name not in sources, "component source roster repeats a path")
        sources[name] = source_identity(root, root / source)
    return {"sources": sources, "static": product_identity(root, static, "static"),
            "dynamic": product_identity(root, dynamic, "dynamic")}


def _helper_module(dynamic: Path):
    helper = dynamic / "share/crabc/crabc_cc_static.py"
    try:
        metadata = helper.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
                "dynamic compiler helper is not physical")
        spec = importlib.util.spec_from_file_location("owned_text_locale_numeric_component_tools", helper)
        require(spec is not None and spec.loader is not None, "cannot load dynamic compiler helper")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return spec, module
    except (OSError, ImportError, RuntimeError) as error:
        raise ReceiptError("cannot load dynamic compiler helper") from error


def tool_identity(root: Path, path: Path, label: str) -> dict[str, object]:
    try:
        path = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is absent") from error
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            f"{label} is not physical")
    return {"path": mounted(root, path), "sha256": digest(path), "size": metadata.st_size}


def tool_roster(root: Path, static: Path, dynamic: Path) -> dict[str, object]:
    """Record every compiler/linker/query binary used by the finite runner."""

    spec, module = _helper_module(dynamic)
    try:
        return {
            "oracle": tool_identity(root, ORACLE_CC, "pinned musl compiler"),
            "dynamic_driver": tool_identity(root, dynamic / "bin/crabc-cc-dynamic", "dynamic driver"),
            "static_driver": tool_identity(root, static / "bin/crabc-cc", "static driver"),
            "compiler": tool_identity(root, Path(module.compiler()), "resolved compiler"),
            "linker": tool_identity(root, Path(module.linker(dynamic)), "resolved linker"),
            "nm": tool_identity(root, Path(providers.NM), "nm"),
            "readelf": tool_identity(root, Path(providers.READELF), "readelf"),
        }
    finally:
        sys.modules.pop(spec.name, None)


def check_elf_rel(path: Path, label: str) -> None:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ReceiptError(f"cannot read {label}") from error
    require(len(data) >= 20 and data[:7] == b"\x7fELF\x02\x01\x01" and data[16:18] == b"\x01\x00"
            and data[18:20] == b">\x00", f"{label} is not an x86-64 ET_REL object")


def expected_command_stems() -> tuple[str, ...]:
    stems: list[str] = ["source-product-before", "tools-before"]
    for role, _relative, _define, _group in contract.all_object_roles():
        stems.extend((f"header-{role}", f"compile-{role}"))
    stems.extend(("combine", "combine-source-specific", "normal-imports", "dynamic-provider-symbols", "static-provider-symbols",
                  "component-preflight", "component-collector"))
    for workload in WORKLOADS:
        stems.extend((f"oracle-{workload}-link", f"oracle-{workload}-run"))
        for linkage in ("static", "static-pie"):
            stems.extend((f"{workload}-{linkage}-link", f"{workload}-{linkage}-validate",
                          f"{workload}-{linkage}-run"))
        for mode in ("pie", "non-pie"):
            prefix = f"{workload}-dynamic-{mode}"
            stems.extend((f"{prefix}-link", f"{prefix}-validate", f"{prefix}-copy-before",
                          f"{prefix}-copy-audit-before", f"{prefix}-kernel", f"{prefix}-direct",
                          f"{prefix}-copy-audit-after"))
    for linkage in ("static", "static-pie"):
        stems.extend((f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-link",
                      f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-validate",
                      f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-run"))
    for mode in ("pie", "non-pie"):
        prefix = f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}"
        stems.extend((f"{prefix}-link", f"{prefix}-validate", f"{prefix}-copy-before",
                      f"{prefix}-copy-audit-before", f"{prefix}-kernel", f"{prefix}-direct",
                      f"{prefix}-copy-audit-after"))
    stems.extend((*ALIAS_SYMBOL_STEMS, "alias-symbol-observation", "tools-after", "source-product-after"))
    require(len(stems) == len(set(stems)), "component command stem roster repeats a name")
    return tuple(stems)


def _receipt_command(action: str, root: Path, work: Path, static: Path, dynamic: Path, output: Path) -> list[str]:
    return ["python3", "-B", mounted(root, root / RECEIPT), action, "--root", SOURCE_MOUNT,
            "--static", mounted(root, static), "--dynamic", mounted(root, dynamic),
            "--output", mounted(root, output)]


def _provider_command(root: Path, work: Path) -> list[str]:
    return ["python3", "-B", mounted(root, root / PROVIDER), "--imports", mounted(root, work / "normal-imports.stdout"),
            "--dynamic-definitions", mounted(root, work / "dynamic-provider-symbols.stdout"),
            "--static-definitions", mounted(root, work / "static-provider-symbols.stdout")]


def _link_validation_command(root: Path, product: Path, workload: Path, executable: Path,
                             receipt: Path, linkage: str, *, export_dynamic: bool) -> list[str]:
    # ``-`` is a fixed small adapter whose bytes are in the retained raw argv
    # and whose output is independently reconstructed from the public link receipt.
    return ["python3", "-B", "-", SOURCE_MOUNT, mounted(root, product), mounted(root, workload),
            mounted(root, executable), mounted(root, receipt), linkage, "1" if export_dynamic else "0"]


def _payload_command(action: str, root: Path, dynamic: Path, root_copy: Path,
                     executable: Path, record: Path) -> list[str]:
    return ["python3", "-B", mounted(root, root / COPIES), action, "--product", mounted(root, dynamic),
            "--execution-root", mounted(root, root_copy), "--source-consumer", mounted(root, executable),
            "--execution-consumer", mounted(root, root_copy / "consumer"), "--record", mounted(root, record)]


def alias_symbol_commands(root: Path, work: Path, static: Path, dynamic: Path) -> dict[str, list[str]]:
    """The exact selected alias-table commands, separate from normal imports."""

    result = {
        "oracle-static-symbols": [providers.READELF, "-Ws", "/opt/musl-1.2.6/lib/libc.a"],
        "oracle-dynamic-symbols": [providers.READELF, "--dyn-syms", "-W", "/opt/musl-1.2.6/lib/libc.so"],
        "oracle-shared-symbols": [providers.READELF, "-Ws", "/opt/musl-1.2.6/lib/libc.so"],
        "candidate-static-symbols": [providers.READELF, "-Ws", mounted(root, static / "usr/lib/libc.a")],
        "candidate-dynamic-symbols": [providers.READELF, "--dyn-syms", "-W", mounted(root, dynamic / "usr/lib/libc.so")],
        "candidate-shared-symbols": [providers.READELF, "-Ws", mounted(root, dynamic / "usr/lib/libc.so")],
        "executable-dynamic-pie-symbols": [providers.READELF, "--dyn-syms", "-W",
                                             mounted(root, executable_path(work, "alias", "dynamic-pie"))],
        "executable-dynamic-non-pie-symbols": [providers.READELF, "--dyn-syms", "-W",
                                                 mounted(root, executable_path(work, "alias", "dynamic-non-pie"))],
    }
    result["alias-symbol-observation"] = [
        "python3", "-B", mounted(root, root / ALIAS_SYMBOLS), mounted(root, root / ALIAS_CONTRACT),
        *(mounted(root, work / f"{stem}.stdout") for stem in ALIAS_SYMBOL_STEMS),
        mounted(root, work / "alias-observation.json"),
    ]
    return result


def command_plan(root: Path, work: Path, static: Path, dynamic: Path,
                 tools: Mapping[str, object]) -> dict[str, list[str]]:
    """Return every retained argv for one full six-cell product pair."""

    require(isinstance(tools, Mapping), "tool roster is malformed")
    tool = lambda name: str(tools[name]["path"])
    plan: dict[str, list[str]] = {
        "source-product-before": _receipt_command("seal", root, work, static, dynamic,
                                                    work / "source-product-before.json"),
        "tools-before": _receipt_command("tools", root, work, static, dynamic, work / "tools-before.json"),
    }
    compiler = providers.compiler_path(dynamic)
    for role, source, define, _group in contract.all_object_roles():
        plan[f"header-{role}"] = providers.header_argv(root, dynamic, compiler, source, define,
                                                         source_mount=SOURCE_MOUNT)
        plan[f"compile-{role}"] = providers.compile_argv(root, work, dynamic, role, source, define,
                                                           source_mount=SOURCE_MOUNT)
    normal_objects = [mounted(root, work / f"{role}.o") for role, _source, _define, group in contract.OBJECT_ROLES
                      if group == "normal"]
    plan["combine"] = [tool("linker"), "-r", "-o", mounted(root, work / "normal-workload.o"), *normal_objects]
    source_specific_objects = [
        mounted(root, work / f"{role}.o")
        for role, _source, _define, group in contract.SOURCE_SPECIFIC_OBJECT_ROLES
        if group == "source-specific"
    ]
    plan["combine-source-specific"] = [tool("linker"), "-r", "-o",
                                         mounted(root, work / "source-specific-workload.o"),
                                         *source_specific_objects]
    plan.update(providers.binary_commands(root, work, static, dynamic, source_mount=SOURCE_MOUNT))
    plan["component-preflight"] = _provider_command(root, work)
    plan["component-collector"] = _provider_command(root, work)
    for workload in WORKLOADS:
        object_pathname = workload_object(work, workload)
        oracle = work / f"oracle-{workload}"
        plan[f"oracle-{workload}-link"] = [tool("oracle"), "-std=c11", "-static", "-fno-pie", "-no-pie",
                                                 mounted(root, object_pathname), "-lm", "-o", mounted(root, oracle)]
        plan[f"oracle-{workload}-run"] = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", mounted(root, oracle)]
        for linkage in ("static", "static-pie"):
            executable = executable_path(work, workload, linkage)
            receipt = link_receipt_path(work, workload, linkage)
            plan[f"{workload}-{linkage}-link"] = [tool("static_driver"), f"-{linkage}", "--link-receipt",
                                                   receipt.name, mounted(root, object_pathname), "-o",
                                                   mounted(root, executable)]
            plan[f"{workload}-{linkage}-validate"] = _link_validation_command(
                root, static, object_pathname, executable, receipt, linkage, export_dynamic=False)
            plan[f"{workload}-{linkage}-run"] = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC",
                                                   mounted(root, executable)]
        for mode in ("pie", "non-pie"):
            linkage = f"dynamic-{mode}"
            executable = executable_path(work, workload, linkage)
            export_dynamic = workload == "alias"
            plan[f"{workload}-{linkage}-link"] = [tool("dynamic_driver"), f"--dynamic-{mode}",
                                                   *( ["-rdynamic"] if export_dynamic else [] ),
                                                   mounted(root, object_pathname), "-o", mounted(root, executable)]
            receipt = link_receipt_path(work, workload, linkage)
            plan[f"{workload}-{linkage}-validate"] = _link_validation_command(
                root, dynamic, object_pathname, executable, receipt, mode, export_dynamic=export_dynamic)
            root_copy = work / f"{workload}-dynamic-{mode}-root"
            record = work / f"{workload}-dynamic-{mode}-execution-payload.json"
            plan[f"{workload}-{linkage}-copy-before"] = _payload_command(
                "record", root, dynamic, root_copy, executable, record)
            plan[f"{workload}-{linkage}-copy-audit-before"] = _payload_command(
                "audit", root, dynamic, root_copy, executable, record)
            plan[f"{workload}-{linkage}-kernel"] = ["chroot", mounted(root, root_copy), "/consumer"]
            plan[f"{workload}-{linkage}-direct"] = ["chroot", mounted(root, root_copy), INTERPRETER, "/consumer"]
            plan[f"{workload}-{linkage}-copy-audit-after"] = _payload_command(
                "audit", root, dynamic, root_copy, executable, record)
    object_pathname = workload_object(work, SOURCE_SPECIFIC_WORKLOAD)
    for linkage in ("static", "static-pie"):
        executable = executable_path(work, SOURCE_SPECIFIC_WORKLOAD, linkage)
        receipt = link_receipt_path(work, SOURCE_SPECIFIC_WORKLOAD, linkage)
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-link"] = [
            tool("static_driver"), f"-{linkage}", "--link-receipt", receipt.name,
            mounted(root, object_pathname), "-o", mounted(root, executable),
        ]
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-validate"] = _link_validation_command(
            root, static, object_pathname, executable, receipt, linkage, export_dynamic=False)
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-run"] = [
            "env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", mounted(root, executable),
        ]
    for mode in ("pie", "non-pie"):
        linkage = f"dynamic-{mode}"
        executable = executable_path(work, SOURCE_SPECIFIC_WORKLOAD, linkage)
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-link"] = [
            tool("dynamic_driver"), f"--dynamic-{mode}", mounted(root, object_pathname), "-o",
            mounted(root, executable),
        ]
        receipt = link_receipt_path(work, SOURCE_SPECIFIC_WORKLOAD, linkage)
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-validate"] = _link_validation_command(
            root, dynamic, object_pathname, executable, receipt, mode, export_dynamic=False)
        root_copy = work / f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}-root"
        record = work / f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}-execution-payload.json"
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-copy-before"] = _payload_command(
            "record", root, dynamic, root_copy, executable, record)
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-copy-audit-before"] = _payload_command(
            "audit", root, dynamic, root_copy, executable, record)
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-kernel"] = [
            "chroot", mounted(root, root_copy), "/consumer",
        ]
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-direct"] = [
            "chroot", mounted(root, root_copy), INTERPRETER, "/consumer",
        ]
        plan[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-copy-audit-after"] = _payload_command(
            "audit", root, dynamic, root_copy, executable, record)
    plan.update(alias_symbol_commands(root, work, static, dynamic))
    plan["tools-after"] = _receipt_command("tools", root, work, static, dynamic, work / "tools-after.json")
    plan["source-product-after"] = _receipt_command("seal", root, work, static, dynamic,
                                                      work / "source-product-after.json")
    require(tuple(plan) == expected_command_stems(), "component command plan order drifted")
    return plan


def expected_cwd(root: Path, work: Path, stem: str) -> str:
    # The static driver insists that its sidecar name be relative to its work
    # directory. All other capture calls deliberately run from the checkout.
    if stem.endswith("-static-link") or stem.endswith("-static-pie-link"):
        return mounted(root, work)
    return SOURCE_MOUNT


def parse_argv(path: Path, label: str) -> list[str]:
    value = read_json(path, f"{label} argv")
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label} argv is malformed")
    return value


def command_record(root: Path, work: Path, stem: str) -> dict[str, object]:
    return {field: identity(root, work / f"{stem}.{suffix}", f"{stem} {field}")
            for field, suffix in (("argv", "argv.json"), ("cwd", "cwd"), ("stdout", "stdout"),
                                  ("stderr", "stderr"), ("status", "status"))}


def validate_command(root: Path, work: Path, stem: str, record: object,
                     expected_argv: list[str]) -> dict[str, Path]:
    require(isinstance(record, dict) and set(record) == {"argv", "cwd", "stdout", "stderr", "status"},
            f"{stem} command record fields differ")
    paths = {field: assert_identity(root, record[field], f"{stem} {field}",
                                    expected=work / f"{stem}.{suffix}")
             for field, suffix in (("argv", "argv.json"), ("cwd", "cwd"), ("stdout", "stdout"),
                                   ("stderr", "stderr"), ("status", "status"))}
    require(paths["status"].read_bytes() == b"0\n", f"{stem} did not succeed")
    require(parse_argv(paths["argv"], stem) == expected_argv, f"{stem} argv differs")
    require(paths["cwd"].read_text(encoding="utf-8") == expected_cwd(root, work, stem) + "\n",
            f"{stem} cwd differs")
    return paths


def source_object_paths(root: Path, work: Path) -> list[Path]:
    return [*(root / source for source in contract.direct_sources()),
            *(work / f"{role}.o" for role, _source, _define, _group in contract.all_object_roles()),
            work / "normal-workload.o", work / "source-specific-workload.o"]


def validate_source_object_checks(root: Path, work: Path, record: object) -> None:
    require(isinstance(record, dict) and set(record) == {"before", "after"},
            "source/object check record differs")
    before = assert_identity(root, record["before"], "source/object before",
                             expected=work / "source-object-before.sha256")
    after = assert_identity(root, record["after"], "source/object after",
                            expected=work / "source-object-after.txt")
    paths = source_object_paths(root, work)
    expected_before = b"".join(f"{digest(path)}  {mounted(root, path)}\n".encode("ascii") for path in paths)
    expected_after = b"".join(f"{mounted(root, path)}: OK\n".encode("utf-8") for path in paths)
    require(before.read_bytes() == expected_before, "source/object before hash list differs")
    require(after.read_bytes() == expected_after, "source/object after check differs")


def validate_source_specific_branches(root: Path) -> None:
    """Keep the candidate-only assertions attributed to their existing sources.

    The source/product seal catches arbitrary edits.  These literal checks make
    the reason for the separate workload durable: these branches are the exact
    macro-gated behavior that cannot be compared with the ordinary Musl rows.
    """

    required_fragments = {
        "compat/x86_64/libc_locale_object_wide_probe.c": (
            "#if defined(CRABC_LOCALE_OBJECT_WIDE_FREESTANDING)",
            'newlocale(LC_ALL_MASK, "en_US.UTF-8", NULL) != NULL || errno != ENOENT',
            '#if defined(CRABC_OWNED_LOCALE_ENVIRONMENT)',
            'environment_locale == NULL || errno != EINTR',
            "uselocale(NULL) != LC_GLOBAL_LOCALE || MB_CUR_MAX != 1",
        ),
        "compat/x86_64/libc_locale_wide_iconv_probe.c": (
            "#ifdef CRABC_LOCALE_WIDE_ICONV_FREESTANDING",
            'iconv_open("ISO-8859-1", "UTF-8") != (iconv_t)-1 || errno != EINVAL',
            'iconv_open("UTF-16", "UTF-8") != (iconv_t)-1 || errno != EINVAL',
            'iconv_open("UCS-2LE", "UTF-8") != (iconv_t)-1 || errno != EINVAL',
        ),
        "compat/x86_64/libc_locale_multibyte_probe.c": (
            "#ifdef CRABC_LOCALE_MULTIBYTE_FREESTANDING",
            '"POSIX;C;C;C;C;C"', '"C;C;C;C;C;C"',
            '"C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8"',
            "silently broadened into a general locale-name parser.",
        ),
    }
    for relative_name, fragments in required_fragments.items():
        try:
            source = (root / relative_name).read_text(encoding="utf-8")
        except OSError as error:
            raise ReceiptError(f"cannot read source-specific branch {relative_name}") from error
        require(all(fragment in source for fragment in fragments),
                f"source-specific branch drifted: {relative_name}")


def validate_framed_stream(stream: bytes, prefix: bytes, roles: tuple[bytes, ...], label: str) -> None:
    """Ensure a retained raw stream has no bytes outside ordered stage frames."""

    position = 0
    for role in roles:
        begin = prefix + role + b":begin\n"
        finish = prefix + role + b":ok\n"
        require(stream.startswith(begin, position), f"{label} {role.decode()} begin frame differs")
        position += len(begin)
        finish_position = stream.find(finish, position)
        require(finish_position >= position, f"{label} {role.decode()} ok frame is absent")
        position = finish_position + len(finish)
    require(position == len(stream), f"{label} stream has bytes outside ordered frames")


def validate_normal_frames(stream: bytes) -> None:
    validate_framed_stream(stream, b"text-locale-numeric/",
                          tuple(role.encode("ascii") for role in NORMAL_FRAME_ROLES), "normal")


def validate_source_specific_frames(stream: bytes) -> None:
    validate_framed_stream(stream, b"text-locale-numeric-source-specific/",
                          (b"locale-object-wide-profile", b"locale-wide-iconv-profile",
                           b"locale-multibyte-profile"), "source-specific")


def _actual_alias_commands(work: Path, static: Path, dynamic: Path) -> dict[str, list[str]]:
    return {
        "oracle-static-symbols": [providers.READELF, "-Ws", "/opt/musl-1.2.6/lib/libc.a"],
        "oracle-dynamic-symbols": [providers.READELF, "--dyn-syms", "-W", "/opt/musl-1.2.6/lib/libc.so"],
        "oracle-shared-symbols": [providers.READELF, "-Ws", "/opt/musl-1.2.6/lib/libc.so"],
        "candidate-static-symbols": [providers.READELF, "-Ws", str(static / "usr/lib/libc.a")],
        "candidate-dynamic-symbols": [providers.READELF, "--dyn-syms", "-W", str(dynamic / "usr/lib/libc.so")],
        "candidate-shared-symbols": [providers.READELF, "-Ws", str(dynamic / "usr/lib/libc.so")],
        "executable-dynamic-pie-symbols": [providers.READELF, "--dyn-syms", "-W",
                                             str(executable_path(work, "alias", "dynamic-pie"))],
        "executable-dynamic-non-pie-symbols": [providers.READELF, "--dyn-syms", "-W",
                                                 str(executable_path(work, "alias", "dynamic-non-pie"))],
    }


def validate_alias_observation(root: Path, work: Path, static: Path, dynamic: Path,
                               commands: Mapping[str, Mapping[str, Path]], identity_record: object) -> None:
    """Replay selected alias tables before trusting the preserved observation JSON."""

    for stem, command in _actual_alias_commands(work, static, dynamic).items():
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False)
        except OSError as error:
            raise ReceiptError(f"cannot replay {stem}") from error
        require(result.returncode == 0 and not result.stderr, f"physical {stem} replay failed")
        require(result.stdout == commands[stem]["stdout"].read_bytes(),
                f"retained {stem} output differs from physical replay")
    observed = alias_symbols.validate_observation(
        root / ALIAS_CONTRACT,
        *(work / f"{stem}.stdout" for stem in ALIAS_SYMBOL_STEMS),
    )
    retained = assert_identity(root, identity_record, "alias observation", expected=work / "alias-observation.json")
    require(read_json(retained, "alias observation") == observed,
            "retained alias observation differs from replayed tables")
    require(commands["alias-symbol-observation"]["stdout"].read_bytes() == b""
            and commands["alias-symbol-observation"]["stderr"].read_bytes() == b"",
            "alias observation collector emitted a stream")


def validate_link(root: Path, work: Path, static: Path, dynamic: Path, tools: Mapping[str, object],
                  commands: Mapping[str, Mapping[str, Path]], links: Mapping[str, object],
                  workload: str, linkage: str) -> None:
    product = static if linkage in {"static", "static-pie"} else dynamic
    public_linkage = linkage if linkage in {"static", "static-pie"} else linkage.removeprefix("dynamic-")
    export_dynamic = workload == "alias" and public_linkage in {"pie", "non-pie"}
    executable = executable_path(work, workload, linkage)
    receipt = link_receipt_path(work, workload, linkage)
    try:
        reconstructed = product_evidence.validate_retained_link(
            root, SOURCE_MOUNT, product, workload_object(work, workload), executable, receipt, public_linkage,
            {name: tools["linker"][name] for name in ("path", "sha256")}, export_dynamic=export_dynamic,
        )
    except (product_evidence.ProductEvidenceError, OSError, ValueError) as error:
        raise ReceiptError(f"{workload} {linkage} retained link differs") from error
    expected = dict(reconstructed)
    expected["product"] = mounted(root, product)
    retained = assert_identity(root, links[linkage], f"{workload} {linkage} product link",
                               expected=product_link_path(work, workload, linkage))
    require(read_json(retained, f"{workload} {linkage} product link") == expected,
            f"{workload} {linkage} product-link differs from reconstructed link")
    require(commands[f"{workload}-{linkage}-validate"]["stdout"].read_bytes() == canonical(expected),
            f"{workload} {linkage} link validation stream differs")


def validate_payload(root: Path, work: Path, dynamic: Path,
                     commands: Mapping[str, Mapping[str, Path]], payloads: Mapping[str, object],
                     workload: str, mode: str) -> None:
    require(isinstance(payloads, Mapping) and mode in payloads, f"{workload} {mode} payload is absent")
    item = payloads[mode]
    require(isinstance(item, dict) and set(item) == {"record", "before", "after"},
            f"{workload} {mode} payload fields differ")
    root_copy = work / f"{workload}-dynamic-{mode}-root"
    executable = executable_path(work, workload, f"dynamic-{mode}")
    record = assert_identity(root, item["record"], f"{workload} {mode} payload record",
                             expected=work / f"{workload}-dynamic-{mode}-execution-payload.json")
    try:
        audited = payload_evidence.audit_execution_payload(dynamic, root_copy, executable, root_copy / "consumer", record)
    except payload_evidence.CryptRuntimeEvidenceError as error:
        raise ReceiptError(f"{workload} {mode} copied payload differs") from error
    expected = canonical(audited)
    for point in ("before", "after"):
        expected_path = work / f"{workload}-dynamic-{mode}-copy-audit-{point}.stdout"
        audited_path = assert_identity(root, item[point], f"{workload} {mode} payload {point}", expected=expected_path)
        require(audited_path.read_bytes() == expected, f"{workload} {mode} payload {point} audit differs")


def make_report(root: Path, work: Path, static: Path, dynamic: Path) -> dict[str, object]:
    """Build the public per-pair report after the runner has retained all raw files."""

    root = root.resolve(strict=True)
    work = physical_directory(root, relative(root, work, "component work"), "component work")
    static = physical_directory(root, relative(root, static, "static product"), "static product")
    dynamic = physical_directory(root, relative(root, dynamic, "dynamic product"), "dynamic product")
    plan = command_plan(root, work, static, dynamic, tool_roster(root, static, dynamic))
    return {
        "schema": REPORT_SCHEMA,
        "scope": list(contract.CAPABILITIES),
        "rows": row_records(),
        "abi_contract": contract.ABI_CONTRACT,
        "source_objects": {name: identity(root, object_path(work, name), f"source object {name}")
                           for name in (*[role for role, _source, _define, _group in contract.all_object_roles()],
                                        "normal-workload", "source-specific-workload")},
        "products": {"static": relative(root, static, "static product").as_posix(),
                     "dynamic": relative(root, dynamic, "dynamic product").as_posix()},
        "seals": {name: identity(root, work / f"{name}.json", f"{name} seal")
                  for name in ("source-product-before", "source-product-after", "tools-before", "tools-after")},
        "provider_evidence": {
            "normal": identity(root, work / "component-collector.stdout", "normal provider evidence"),
            "alias": identity(root, work / "alias-observation.json", "alias provider evidence"),
        },
        "commands": {stem: command_record(root, work, stem) for stem in plan},
        "links": {workload: {linkage: identity(root, product_link_path(work, workload, linkage),
                                                f"{workload} {linkage} product link")
                               for linkage in LINKAGES} for workload in WORKLOADS},
        "execution_payloads": {
            workload: {mode: {
                "record": identity(root, work / f"{workload}-dynamic-{mode}-execution-payload.json",
                                   f"{workload} {mode} payload record"),
                "before": identity(root, work / f"{workload}-dynamic-{mode}-copy-audit-before.stdout",
                                   f"{workload} {mode} payload before"),
                "after": identity(root, work / f"{workload}-dynamic-{mode}-copy-audit-after.stdout",
                                  f"{workload} {mode} payload after"),
            } for mode in ("pie", "non-pie")} for workload in WORKLOADS},
        "source_object_checks": {
            "before": identity(root, work / "source-object-before.sha256", "source/object before"),
            "after": identity(root, work / "source-object-after.txt", "source/object after"),
        },
        "source_specific_evidence": {
            "rows": source_specific_row_records(),
            "oracle_relation": SOURCE_SPECIFIC_ORACLE_RELATION,
            "unclosed_gaps": list(SOURCE_SPECIFIC_UNCLOSED_GAPS),
            "execution_cells": list(SOURCE_SPECIFIC_EXECUTION_CELLS),
            "links": {
                linkage: identity(root, product_link_path(work, SOURCE_SPECIFIC_WORKLOAD, linkage),
                                   f"{SOURCE_SPECIFIC_WORKLOAD} {linkage} product link")
                for linkage in LINKAGES
            },
            "execution_payloads": {
                mode: {
                    "record": identity(root, work / f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}-execution-payload.json",
                                       f"{SOURCE_SPECIFIC_WORKLOAD} {mode} payload record"),
                    "before": identity(root, work / f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}-copy-audit-before.stdout",
                                       f"{SOURCE_SPECIFIC_WORKLOAD} {mode} payload before"),
                    "after": identity(root, work / f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}-copy-audit-after.stdout",
                                      f"{SOURCE_SPECIFIC_WORKLOAD} {mode} payload after"),
                } for mode in ("pie", "non-pie")
            },
        },
        "execution_cells": list(EXECUTION_CELLS),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }


def _products_for_report(root: Path, report: Mapping[str, object], expected_products: Mapping[str, Path] | None) -> tuple[Path, Path]:
    products = report["products"]
    require(isinstance(products, dict) and set(products) == {"static", "dynamic"}, "report product roster differs")
    static = physical_directory(root, Path(products["static"]), "report static product") if isinstance(products["static"], str) else None
    dynamic = physical_directory(root, Path(products["dynamic"]), "report dynamic product") if isinstance(products["dynamic"], str) else None
    require(static is not None and dynamic is not None, "report product path is malformed")
    if expected_products is not None:
        require(static == expected_products["static"] and dynamic == expected_products["dynamic"],
                "report does not use the named POSIX product pair")
    return static, dynamic


def validate_report(root: Path, report_path: Path, *, expected_products: Mapping[str, Path] | None = None) -> tuple[dict[str, object], dict[str, bytes]]:
    """Replay one report against its physical sources, products, and raw artifacts."""

    root = root.resolve(strict=True)
    report_path = physical_file(root, relative(root, report_path, "component report"), "component report")
    require(report_path.name == "owned-text-locale-numeric.json" and report_path.parent.is_relative_to(root / ".work"),
            "component report is not a retained checkout-local report")
    report = read_json(report_path, "component report")
    require(isinstance(report, dict) and set(report) == set(REPORT_FIELDS), "component report fields differ")
    require(report["schema"] == REPORT_SCHEMA and report["scope"] == list(contract.CAPABILITIES)
            and report["rows"] == row_records() and report["abi_contract"] == contract.ABI_CONTRACT,
            "component report contract differs")
    require(report["execution_cells"] == list(EXECUTION_CELLS), "component execution-cell roster differs")
    require(all(report[flag] is False for flag in ("family_completion", "promotion_ready", "public_support")),
            "component report is promoting")
    static, dynamic = _products_for_report(root, report, expected_products)
    work = report_path.parent
    object_names = {role for role, _source, _define, _group in contract.all_object_roles()} | {
        "normal-workload", "source-specific-workload",
    }
    source_objects = report["source_objects"]
    require(isinstance(source_objects, dict) and set(source_objects) == object_names,
            "source object roster differs")
    object_bytes: dict[str, bytes] = {}
    for name in sorted(object_names):
        path = assert_identity(root, source_objects[name], f"source object {name}", expected=object_path(work, name))
        check_elf_rel(path, f"source object {name}")
        object_bytes[name] = path.read_bytes()
    seals = report["seals"]
    require(isinstance(seals, dict) and set(seals) == {
        "source-product-before", "source-product-after", "tools-before", "tools-after",
    }, "component seal roster differs")
    expected_source = source_product_seal(root, static, dynamic)
    for name in ("source-product-before", "source-product-after"):
        path = assert_identity(root, seals[name], f"{name} seal", expected=work / f"{name}.json")
        require(read_json(path, name) == expected_source, f"{name} source/product seal differs")
    expected_tools = tool_roster(root, static, dynamic)
    for name in ("tools-before", "tools-after"):
        path = assert_identity(root, seals[name], f"{name} seal", expected=work / f"{name}.json")
        require(read_json(path, name) == expected_tools, f"{name} tool seal differs")
    validate_source_object_checks(root, work, report["source_object_checks"])
    plan = command_plan(root, work, static, dynamic, expected_tools)
    commands = report["commands"]
    require(isinstance(commands, dict) and set(commands) == set(plan), "component command roster differs")
    raw = {stem: validate_command(root, work, stem, commands[stem], argv) for stem, argv in plan.items()}
    try:
        providers.validate_invocations(root, work, dynamic, source_mount=SOURCE_MOUNT)
    except providers.EvidenceError as error:
        raise ReceiptError(f"installed header/compile evidence differs: {error}") from error
    retained_queries = {name: raw[name]["stdout"].read_bytes()
                        for name in ("normal-imports", "dynamic-provider-symbols", "static-provider-symbols")}
    try:
        physical_providers = providers.replay_binary_queries(root, work, static, dynamic, retained_queries)
    except providers.EvidenceError as error:
        raise ReceiptError(f"physical normal provider replay differs: {error}") from error
    normal_provider = assert_identity(root, report["provider_evidence"].get("normal")
                                      if isinstance(report["provider_evidence"], dict) else None,
                                      "normal provider evidence", expected=work / "component-collector.stdout")
    require(normal_provider.read_bytes() == canonical(physical_providers)
            and raw["component-preflight"]["stdout"].read_bytes() == canonical(physical_providers),
            "normal provider collector differs from physical replay")
    require(raw["component-collector"]["stderr"].read_bytes() == b""
            and raw["component-preflight"]["stderr"].read_bytes() == b"",
            "normal provider collector emitted stderr")
    provider_evidence = report["provider_evidence"]
    require(isinstance(provider_evidence, dict) and set(provider_evidence) == {"normal", "alias"},
            "provider evidence roster differs")
    validate_alias_observation(root, work, static, dynamic, raw, provider_evidence["alias"])
    links = report["links"]
    require(isinstance(links, dict) and set(links) == set(WORKLOADS)
            and all(isinstance(links[workload], dict) and set(links[workload]) == set(LINKAGES)
                    for workload in WORKLOADS), "component link roster differs")
    for workload in WORKLOADS:
        for linkage in LINKAGES:
            validate_link(root, work, static, dynamic, expected_tools, raw, links[workload], workload, linkage)
    payloads = report["execution_payloads"]
    require(isinstance(payloads, dict) and set(payloads) == set(WORKLOADS)
            and all(isinstance(payloads[workload], dict) and set(payloads[workload]) == {"pie", "non-pie"}
                    for workload in WORKLOADS), "component copied-payload roster differs")
    for workload in WORKLOADS:
        oracle = raw[f"oracle-{workload}-run"]
        require(oracle["stderr"].read_bytes() == b"", f"pinned musl {workload} oracle emitted stderr")
        if workload == "normal":
            validate_normal_frames(oracle["stdout"].read_bytes())
        for linkage in ("static", "static-pie"):
            candidate = raw[f"{workload}-{linkage}-run"]
            require(candidate["stdout"].read_bytes() == oracle["stdout"].read_bytes()
                    and candidate["stderr"].read_bytes() == oracle["stderr"].read_bytes()
                    and candidate["status"].read_bytes() == oracle["status"].read_bytes(),
                    f"{workload} {linkage} differs from the pinned musl oracle")
        for mode in ("pie", "non-pie"):
            for entry in ("kernel", "direct"):
                candidate = raw[f"{workload}-dynamic-{mode}-{entry}"]
                require(candidate["stdout"].read_bytes() == oracle["stdout"].read_bytes()
                        and candidate["stderr"].read_bytes() == oracle["stderr"].read_bytes()
                        and candidate["status"].read_bytes() == oracle["status"].read_bytes(),
                        f"{workload} dynamic {mode} {entry} differs from the pinned musl oracle")
            validate_payload(root, work, dynamic, raw, payloads[workload], workload, mode)
    supplemental = report["source_specific_evidence"]
    require(isinstance(supplemental, dict) and set(supplemental) == {
        "rows", "oracle_relation", "unclosed_gaps", "execution_cells", "links", "execution_payloads",
    }, "source-specific evidence fields differ")
    require(supplemental["rows"] == source_specific_row_records()
            and supplemental["oracle_relation"] == SOURCE_SPECIFIC_ORACLE_RELATION
            and supplemental["unclosed_gaps"] == list(SOURCE_SPECIFIC_UNCLOSED_GAPS)
            and supplemental["execution_cells"] == list(SOURCE_SPECIFIC_EXECUTION_CELLS),
            "source-specific evidence contract differs")
    validate_source_specific_branches(root)
    baseline = raw[f"{SOURCE_SPECIFIC_WORKLOAD}-static-run"]
    require(baseline["stderr"].read_bytes() == b"", "candidate static source-specific baseline emitted stderr")
    validate_source_specific_frames(baseline["stdout"].read_bytes())
    source_specific_links = supplemental["links"]
    require(isinstance(source_specific_links, dict) and set(source_specific_links) == set(LINKAGES),
            "source-specific link roster differs")
    for linkage in LINKAGES:
        validate_link(root, work, static, dynamic, expected_tools, raw, source_specific_links,
                      SOURCE_SPECIFIC_WORKLOAD, linkage)
    for linkage in ("static-pie",):
        candidate = raw[f"{SOURCE_SPECIFIC_WORKLOAD}-{linkage}-run"]
        require(candidate["stdout"].read_bytes() == baseline["stdout"].read_bytes()
                and candidate["stderr"].read_bytes() == baseline["stderr"].read_bytes()
                and candidate["status"].read_bytes() == baseline["status"].read_bytes(),
                f"candidate {linkage} source-specific transcript differs from static baseline")
    source_specific_payloads = supplemental["execution_payloads"]
    require(isinstance(source_specific_payloads, dict) and set(source_specific_payloads) == {"pie", "non-pie"},
            "source-specific copied-payload roster differs")
    for mode in ("pie", "non-pie"):
        for entry in ("kernel", "direct"):
            candidate = raw[f"{SOURCE_SPECIFIC_WORKLOAD}-dynamic-{mode}-{entry}"]
            require(candidate["stdout"].read_bytes() == baseline["stdout"].read_bytes()
                    and candidate["stderr"].read_bytes() == baseline["stderr"].read_bytes()
                    and candidate["status"].read_bytes() == baseline["status"].read_bytes(),
                    f"candidate dynamic {mode} {entry} source-specific transcript differs from static baseline")
        validate_payload(root, work, dynamic, raw, source_specific_payloads, SOURCE_SPECIFIC_WORKLOAD, mode)
    return report, object_bytes


def _relative_report(root: Path, value: Path) -> Path:
    return physical_file(root, relative(root, value, "pair report"), "pair report")


def collect(root: Path, static_preparation: Path, dynamic_qualification: Path,
            reports: Mapping[str, Path]) -> dict[str, object]:
    """Collect three source-matched product-pair reports into one 18-cell receipt."""

    root = root.resolve(strict=True)
    require(set(reports) == set(PAIR_NAMES), "receipt requires primary, reproduction, and extracted reports")
    request = {"schema": family.SCHEMA, "source_mount": str(root),
               "static_preparation": relative(root, static_preparation, "static preparation").as_posix(),
               "dynamic_qualification": relative(root, dynamic_qualification, "dynamic qualification").as_posix()}
    inputs, products = family.input_products(root, request)
    report_paths: dict[str, Path] = {}
    pair_roots: dict[str, str] = {}
    pairs: dict[str, dict[str, object]] = {}
    canonical_objects: dict[str, bytes] | None = None
    used_products: set[tuple[Path, Path]] = set()
    for pair in PAIR_NAMES:
        path = _relative_report(root, reports[pair])
        report_paths[pair] = path
        pair_root = physical_directory(root, relative(root, path.parent, f"{pair} evidence root"),
                                       f"{pair} evidence root")
        pair_roots[pair] = relative(root, pair_root, f"{pair} evidence root").as_posix()
        report, objects = validate_report(root, path, expected_products=products[pair])
        product_pair = (products[pair]["static"], products[pair]["dynamic"])
        require(product_pair not in used_products, "receipt reuses a POSIX product pair")
        used_products.add(product_pair)
        if canonical_objects is None:
            canonical_objects = objects
        else:
            require(objects == canonical_objects, "installed-header ET_REL object bytes differ across pairs")
        pairs[pair] = {"report": relative(root, path, f"{pair} report").as_posix(), "report_sha256": digest(path),
                       "execution_cells": list(report["execution_cells"])}
    return {
        "schema": SCHEMA,
        # This exact two-field source shape is the POSIX family boundary; do
        # not add a component-specific source record here.
        "source": static_products.source_identity(root),
        "inputs": {"static_preparation": request["static_preparation"],
                   "dynamic_qualification": request["dynamic_qualification"], "evidence": inputs},
        "products": {pair: {kind: relative(root, products[pair][kind], f"{pair} {kind} product").as_posix()
                             for kind in ("static", "dynamic")} for pair in PAIR_NAMES},
        "rows": row_records(),
        "pair_evidence_roots": pair_roots,
        "pairs": pairs,
        "cell_count": len(PAIR_NAMES) * len(EXECUTION_CELLS),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }


def validate(root: Path, receipt: object) -> dict[str, object]:
    """Validate an aggregate mapping and return the exact reconstructed mapping.

    This is the stable public adapter consumed by the family coordinator.  It
    deliberately accepts the already-decoded mapping so the coordinator can
    own its outer receipt format and snapshot the three declared evidence roots.
    """

    root = root.resolve(strict=True)
    require(isinstance(receipt, dict) and set(receipt) == set(RECEIPT_FIELDS),
            "aggregate receipt fields differ")
    require(receipt["schema"] == SCHEMA and receipt["rows"] == row_records()
            and receipt["cell_count"] == len(PAIR_NAMES) * len(EXECUTION_CELLS),
            "aggregate receipt contract differs")
    require(all(receipt[flag] is False for flag in ("family_completion", "promotion_ready", "public_support")),
            "aggregate receipt is promoting")
    inputs = receipt["inputs"]
    require(isinstance(inputs, dict) and set(inputs) == {"static_preparation", "dynamic_qualification", "evidence"},
            "aggregate input fields differ")
    require(all(isinstance(inputs[name], str) for name in ("static_preparation", "dynamic_qualification")),
            "aggregate input paths differ")
    pairs = receipt["pairs"]
    roots = receipt["pair_evidence_roots"]
    require(isinstance(pairs, dict) and set(pairs) == set(PAIR_NAMES)
            and isinstance(roots, dict) and set(roots) == set(PAIR_NAMES), "aggregate pair roster differs")
    reports: dict[str, Path] = {}
    for pair in PAIR_NAMES:
        item = pairs[pair]
        require(isinstance(item, dict) and set(item) == {"report", "report_sha256", "execution_cells"},
                f"{pair} aggregate pair fields differ")
        require(isinstance(item["report"], str) and isinstance(item["report_sha256"], str)
                and len(item["report_sha256"]) == 64 and item["execution_cells"] == list(EXECUTION_CELLS),
                f"{pair} aggregate pair values differ")
        report = physical_file(root, Path(item["report"]), f"{pair} report")
        evidence_root = physical_directory(root, Path(roots[pair]), f"{pair} evidence root")
        require(report.parent == evidence_root, f"{pair} report is not a direct child of its evidence root")
        require(digest(report) == item["report_sha256"], f"{pair} report hash differs")
        reports[pair] = report
    observed = collect(root, root / inputs["static_preparation"], root / inputs["dynamic_qualification"], reports)
    require(family.same_json(receipt, observed), "aggregate receipt differs from reconstructed evidence")
    return observed


def _write_json(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise ReceiptError(f"refuses to replace retained file: {path}")
    path.write_bytes(canonical(value))


def _report_argument(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or name not in PAIR_NAMES or not path:
        raise argparse.ArgumentTypeError("report must be NAME=CHECKOUT_RELATIVE_PATH")
    return name, Path(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("seal", "tools"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--static", type=Path, required=True)
        command.add_argument("--dynamic", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    report = commands.add_parser("write-report")
    report.add_argument("--root", type=Path, required=True)
    report.add_argument("--work", type=Path, required=True)
    report.add_argument("--static", type=Path, required=True)
    report.add_argument("--dynamic", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("validate-report")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--report", type=Path, required=True)
    aggregate = commands.add_parser("collect")
    aggregate.add_argument("--root", type=Path, required=True)
    aggregate.add_argument("--static-preparation", type=Path, required=True)
    aggregate.add_argument("--dynamic-qualification", type=Path, required=True)
    aggregate.add_argument("--report", type=_report_argument, action="append", required=True)
    aggregate.add_argument("--output", type=Path)
    verify = commands.add_parser("validate")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "seal":
            _write_json(args.output, source_product_seal(args.root, args.static, args.dynamic))
        elif args.command == "tools":
            _write_json(args.output, tool_roster(args.root, args.static, args.dynamic))
        elif args.command == "write-report":
            _write_json(args.output, make_report(args.root, args.work, args.static, args.dynamic))
        elif args.command == "validate-report":
            validate_report(args.root, args.report)
            print("owned text/locale/numeric component receipt: valid; bounded evidence remains non-promoting")
        elif args.command == "collect":
            reports = dict(args.report)
            require(len(reports) == len(args.report), "each aggregate report name may appear once")
            record = collect(args.root, args.static_preparation, args.dynamic_qualification, reports)
            if args.output is not None:
                _write_json(args.output, record)
            else:
                print(canonical(record).decode("utf-8"), end="")
        else:
            receipt_path = physical_file(args.root, relative(args.root, args.receipt, "aggregate receipt"),
                                         "aggregate receipt")
            validate(args.root, read_json(receipt_path, "aggregate receipt"))
            print("owned text/locale/numeric aggregate receipt: valid; bounded evidence remains non-promoting")
    except (ReceiptError, OSError, ValueError, product_evidence.ProductEvidenceError,
            payload_evidence.CryptRuntimeEvidenceError, family.ExecutionError,
            static_products.PreparationError, contract.ContractError, providers.EvidenceError,
            alias_symbols.LocaleAliasError) as error:
        parser.exit(1, f"owned text/locale/numeric component receipt failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
