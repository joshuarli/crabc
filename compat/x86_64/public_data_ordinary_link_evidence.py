#!/usr/bin/env python3
"""Retain ordinary link and addressability evidence for selected public data.

This component consumes already prepared static and materialized dynamic
products. It never invokes either sysroot builder and has no qualification,
family-completion, or public-support authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Mapping

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import native_abi_inventory as inventory
import native_abi_selection as selection
import owned_dynamic_qualification as qualification
import owned_posix_product_evidence as products
import owned_posix_static_products as static_products
import owned_static_consumer_matrix as consumer_matrix
import owned_wordexp_evidence as wordexp

SCHEMA = "crabc.x86_64-public-data-ordinary-link/v2"
IMAGE_ENV = "CRABC_X86_PUBLIC_DATA_IMAGE_ID"
IMAGE_PATTERN = re.compile(r"crabc-core-evidence@sha256:[0-9a-f]{64}")
SOURCE_MOUNT = "/workspace"
PROBE = ROOT / "compat/x86_64/public_data_ordinary_link_probe.c"
SELECTION = ROOT / "compat/x86_64/native-abi-selection.toml"
EXPECTED_OBJECT_COUNT = 32
EXPECTED_ALIAS_COUNT = 10
STATIC_MODES = ("static", "static-pie")
DYNAMIC_MODES = ("dynamic-pie", "dynamic-non-pie")
ORACLE_MODES = ("oracle-static", "oracle-dynamic-pie", "oracle-dynamic-non-pie")
CANDIDATE_MODES = (*STATIC_MODES, *DYNAMIC_MODES)
ALL_EXECUTABLES = (*ORACLE_MODES, *CANDIDATE_MODES)
EXECUTABLE_ELF_MODES = {
    "oracle-static": {"type": "EXEC", "interpreter": None},
    "static": {"type": "EXEC", "interpreter": None},
    "static-pie": {"type": "DYN", "interpreter": None},
    "oracle-dynamic-pie": {"type": "DYN", "interpreter": "/lib/ld-musl-x86_64.so.1"},
    "oracle-dynamic-non-pie": {"type": "EXEC", "interpreter": "/lib/ld-musl-x86_64.so.1"},
    "dynamic-pie": {"type": "DYN", "interpreter": "/lib/ld-crabc-x86_64.so.1"},
    "dynamic-non-pie": {"type": "EXEC", "interpreter": "/lib/ld-crabc-x86_64.so.1"},
}
EXECUTION_LABELS = (
    "oracle-static-run",
    "static-run",
    "static-pie-run",
    "oracle-dynamic-pie-kernel",
    "oracle-dynamic-pie-direct",
    "oracle-dynamic-non-pie-kernel",
    "oracle-dynamic-non-pie-direct",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
ABI_ONLY_NAMES = frozenset((
    "___environ", "__daylight", "__environ", "__optpos", "__optreset",
    "__progname", "__progname_full", "__signgam", "__stack_chk_guard",
    "__timezone", "__tzname", "_environ",
))
EXPECTED_STDOUT = b"public-data-ordinary-link-ok\n"
COMMAND_TIMEOUT_SECONDS = 60
TERMINATION_GRACE_SECONDS = 3


class PublicDataEvidenceError(ValueError):
    """An input or retained result cannot prove the bounded data property."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicDataEvidenceError(message)


def digest(path: Path) -> str:
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"not a physical regular file: {path}")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def same_json(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def read_json(path: Path, description: str, expected_type: type[object] = dict) -> Any:
    """Read one strictly finite JSON value with the caller's required root type.

    Raw command artifacts are JSON arrays while receipts are objects.  Keeping
    the root-type check at the call site prevents an object-only convenience
    reader from making a valid retained command unreplayable.
    """
    require(path.is_file() and not path.is_symlink(), f"{description} is not a physical regular file")
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            require(key not in result, f"{description} has a duplicate JSON key")
            result[key] = value
        return result
    def finite_float(token: str) -> float:
        value = float(token)
        require(math.isfinite(value), f"{description} has a non-finite JSON number")
        return value
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                           parse_float=finite_float,
                           parse_constant=lambda token: (_ for _ in ()).throw(
                               PublicDataEvidenceError(f"{description} has non-JSON number {token}")
                           ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicDataEvidenceError(f"cannot read {description}: {error}") from error
    require(type(value) is expected_type, f"{description} is not a {expected_type.__name__}")
    return value


def physical_work_path(root: Path, value: Path, description: str, *, exists: bool = True) -> Path:
    root = Path(root).absolute()
    path = Path(value).absolute()
    require(".." not in Path(value).parts and path.is_relative_to(root / ".work") and path != root / ".work",
            f"{description} is not below checkout .work")
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            if current.exists() and current.is_symlink():
                raise PublicDataEvidenceError(f"{description} traverses a symlink")
    except OSError as error:
        raise PublicDataEvidenceError(f"cannot inspect {description}") from error
    if exists:
        require(path.exists() and path.resolve() == path, f"{description} is not physical")
    return path


def source_file_identity(root: Path, path: Path, description: str) -> dict[str, Any]:
    root = Path(root).absolute()
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink() and path.resolve() == path and path.is_relative_to(root),
            f"{description} is not a physical checkout file")
    return {"path": path.relative_to(root).as_posix(), "sha256": digest(path), "size": path.stat().st_size}


def work_file_identity(root: Path, path: Path, description: str) -> dict[str, Any]:
    path = physical_work_path(root, path, description)
    require(path.is_file() and not path.is_symlink(), f"{description} is not a physical file")
    return {"path": path.relative_to(root).as_posix(), "sha256": digest(path), "size": path.stat().st_size}


def resolve_work_identity(root: Path, value: object, description: str) -> Path:
    require(type(value) is dict and set(value) == {"path", "sha256", "size"},
            f"{description} identity fields differ")
    relative = value["path"]
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts, f"{description} identity path differs")
    path = physical_work_path(root, root / relative, description)
    require(path.is_file() and not path.is_symlink(), f"{description} is not a physical file")
    actual = work_file_identity(root, path, description)
    require(same_json(actual, value), f"{description} bytes differ")
    return path


def mounted(root: Path, path: Path) -> str:
    root = Path(root).absolute()
    path = Path(path).absolute()
    require(path.is_relative_to(root), "mounted path escapes checkout")
    return SOURCE_MOUNT + "/" + path.relative_to(root).as_posix()


def selected_objects(contract: Mapping[str, Any] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if contract is None:
        contract = selection.load_contract()
    contract = selection.validate_contract(dict(contract))
    raw = contract["object_contracts"]
    objects = [dict(row) for row in raw if set(row["artifacts"]) == {"candidate-static", "candidate-shared"}]
    require(len(objects) == EXPECTED_OBJECT_COUNT, "ordinary-link selection does not contain exactly 32 static/shared objects")
    names = [item["name"] for item in objects]
    require(len(names) == len(set(names)), "ordinary-link selection has duplicate object names")
    require("_dl_debug_addr" not in names, "shared-only _dl_debug_addr entered ordinary-link selection")
    loader = [item for item in raw if item["name"] == "_dl_debug_addr"]
    require(len(loader) == 1 and loader[0]["artifacts"] == ["candidate-shared"],
            "_dl_debug_addr loader ownership changed")
    aliases = [{"name": item["name"], "target": item["alias_target"]} for item in objects if item["alias_target"]]
    require(len(aliases) == EXPECTED_ALIAS_COUNT, "ordinary-link selection does not contain exactly ten aliases")
    require(set(item["target"] for item in aliases) <= set(names), "ordinary-link alias target is not selected")
    require({item["name"] for item in objects if item["declaration_kind"] == "abi-only"} == ABI_ONLY_NAMES,
            "fixed probe ABI-only declaration set differs from typed policy")
    require(all(item["source_mutable"] is True for item in objects if item["name"] in {"stdin", "stdout", "stderr"}),
            "pointer-slot mutability must remain distinct from installed pointer constness")
    validate_probe_policy(objects, aliases)
    return objects, aliases


def validate_probe_policy(objects: list[Mapping[str, Any]], aliases: list[Mapping[str, str]]) -> None:
    """Require the fixed C address/alignment and alias checks to mirror policy.

    The probe stays a small reviewable C fixture.  Its per-object literals are
    nevertheless contract inputs: a changed typed alignment or source-declared
    alias must not leave an older literal check pretending to cover it.
    """
    try:
        source = PROBE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise PublicDataEvidenceError(f"cannot read fixed ordinary-link probe: {error}") from error
    address_block = re.search(r"static const volatile uintptr_t addresses\[object_count\] = \{(.*?)\n\};", source, re.DOTALL)
    alignment_block = re.search(r"static const unsigned alignments\[object_count\] = \{(.*?)\n\};", source, re.DOTALL)
    require(address_block is not None and alignment_block is not None,
            "fixed ordinary-link probe address/alignment tables differ")
    names = re.findall(r"\(uintptr_t\)&([A-Za-z_][A-Za-z0-9_]*),", address_block.group(1))
    raw_alignments = [item.strip() for item in alignment_block.group(1).replace("\n", " ").split(",") if item.strip()]
    require(len(names) == len(raw_alignments), "fixed ordinary-link probe alignment count differs")
    try:
        alignments = [int(item, 10) for item in raw_alignments]
    except ValueError as error:
        raise PublicDataEvidenceError("fixed ordinary-link probe alignment literal differs") from error
    expected_names = [str(item["name"]) for item in objects]
    require(names == expected_names, "fixed ordinary-link probe object roster differs")
    require(alignments == [item["alignment_bytes"] for item in objects],
            "fixed ordinary-link probe alignment literals differ from typed policy")
    observed_aliases = [
        {"name": left.removeprefix("object_"), "target": right.removeprefix("object_")}
        for left, right in re.findall(
            r"if \(addresses\[(object_[A-Za-z_][A-Za-z0-9_]*)\] != addresses\[(object_[A-Za-z_][A-Za-z0-9_]*)\]\) return [0-9]+;",
            source,
        )
    ]
    require(observed_aliases == [dict(item) for item in aliases],
            "fixed ordinary-link probe alias literals differ from typed policy")


def selection_identity(root: Path) -> dict[str, Any]:
    objects, aliases = selected_objects()
    source_paths = {SELECTION}
    for item in objects:
        for relative in item["sources"]:
            candidate = Path(relative)
            require(not candidate.is_absolute() and ".." not in candidate.parts, "object source reference escapes checkout")
            source_paths.add(ROOT / candidate)
    return {
        "contract": source_file_identity(root, SELECTION, "selection contract"),
        "sources": [source_file_identity(root, path, "selected object source")
                    for path in sorted(source_paths, key=lambda item: item.as_posix())],
        "names": [item["name"] for item in objects],
        "aliases": aliases,
    }


def _preparation_identity(root: Path, preparation: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    path = work_file_identity(root, preparation, "static preparation receipt")
    primary = record["products"]["primary"]
    require(type(primary) is dict and type(primary.get("path")) is str and type(primary.get("manifest")) is dict,
            "static preparation primary product fields differ")
    product = physical_work_path(root, root / primary["path"], "prepared primary static product")
    manifest = work_file_identity(root, product / "share/crabc/manifest.json", "prepared static manifest")
    require(same_json(manifest, primary["manifest"]), "static preparation primary manifest differs")
    source = record.get("source")
    require(type(source) is dict and set(source) == {"revision", "content_sha256"},
            "static preparation source fields differ")
    return {"receipt": path, "source": source, "primary": {
        "path": product.relative_to(root).as_posix(), "manifest": manifest,
    }}


def admit_inputs(root: Path, static_preparation: Path, static_product: Path,
                 dynamic_product: Path) -> dict[str, Any]:
    root = Path(root).absolute()
    static_preparation = physical_work_path(root, static_preparation, "static preparation receipt")
    static_product = physical_work_path(root, static_product, "static product")
    dynamic_product = physical_work_path(root, dynamic_product, "dynamic product")
    try:
        preparation = static_products.validate_receipt(root, static_preparation)
    except (static_products.PreparationError, OSError, ValueError) as error:
        raise PublicDataEvidenceError(f"static preparation is not current: {error}") from error
    static_identity = _preparation_identity(root, static_preparation, preparation)
    expected_static = root / static_identity["primary"]["path"]
    require(static_product == expected_static, "supplied static product is not preparation primary")
    try:
        dynamic_manifest = qualification.product_identity(dynamic_product)
    except (qualification.QualificationError, OSError, ValueError) as error:
        raise PublicDataEvidenceError(f"dynamic product is not current materialization: {error}") from error
    state_path = dynamic_product / "share/crabc/dynamic-product-state.json"
    state = qualification.read(state_path)
    state_identity = work_file_identity(root, state_path, "dynamic product state")
    manifest_identity = work_file_identity(root, dynamic_product / "share/crabc/manifest.json",
                                            "dynamic product manifest")
    require(type(state.get("source_sha256")) is str
            and state["source_sha256"] == static_identity["source"]["content_sha256"],
            "static preparation and dynamic materialization source digests differ")
    source = static_products.source_identity(root)
    require(same_json(source, static_identity["source"]), "static preparation source changed")
    require(state["source_sha256"] == source["content_sha256"], "dynamic materialization source changed")
    return {
        "source": source,
        "static_preparation": static_identity,
        "dynamic_product": {
            "path": dynamic_product.relative_to(root).as_posix(),
            "manifest": manifest_identity,
            "state": state_identity,
            "manifest_sha256": dynamic_manifest,
        },
    }


def fresh_output(root: Path, output: Path) -> Path:
    root = Path(root).absolute()
    output = physical_work_path(root, output, "output", exists=False)
    require(not output.exists() and not output.is_symlink(), "ordinary-link output must be fresh and non-symlinked")
    require(output.parent.is_dir() and not output.parent.is_symlink(), "ordinary-link output parent is unsafe")
    return output


def admit_output_disjoint(root: Path, output: Path, static_preparation: Path,
                          static_product: Path, dynamic_product: Path) -> None:
    """Keep a fresh receipt outside every read-only supplied input cohort."""
    root = Path(root).absolute()
    output = physical_work_path(root, output, "output", exists=False)
    preparation = physical_work_path(root, static_preparation, "static preparation receipt")
    static_product = physical_work_path(root, static_product, "static product")
    dynamic_product = physical_work_path(root, dynamic_product, "dynamic product")
    for protected, description in (
        (preparation.parent, "static preparation cohort"),
        (static_product, "static product"),
        (dynamic_product, "dynamic product"),
    ):
        require(not output.is_relative_to(protected),
                f"ordinary-link output enters supplied {description}")


def write_new_json(path: Path, value: object) -> None:
    require(not path.exists() and not path.is_symlink(), f"evidence output already exists: {path}")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def raw_path(work: Path, label: str, suffix: str) -> Path:
    """Name one collector raw artifact from the command label exactly once."""
    require(re.fullmatch(r"[a-z0-9-]+", label) is not None and suffix in {
        "command.json", "stdout", "stderr", "status",
    }, "ordinary-link raw artifact name differs")
    return work / "raw" / (label + "." + suffix)


TOOL_ROLES = (
    "static_driver", "dynamic_driver", "compiler", "linker", "oracle_wrapper", "env", "readelf", "chroot",
)
ORACLE_STATIC_INPUTS = {
    "libc_a": Path("/opt/musl-1.2.6/lib/libc.a"),
    "Scrt1": Path("/opt/musl-1.2.6/lib/Scrt1.o"),
    "crti": Path("/opt/musl-1.2.6/lib/crti.o"),
    "crtn": Path("/opt/musl-1.2.6/lib/crtn.o"),
}


def fixed_image_tool_identity(path: Path, description: str) -> dict[str, Any]:
    """Seal a known non-symlink image tool at its contractual spelling."""
    try:
        source = inventory.physical_executable(path, description)
        record = inventory.file_record(source, logical_path=str(path))
    except inventory.InventoryError as error:
        raise PublicDataEvidenceError(f"cannot identify {description}: {error}") from error
    return {key: record[key] for key in ("path", "sha256", "mode")}


def retain_tool_snapshot(work: Path, role: str, source: Mapping[str, Any]) -> dict[str, Any]:
    """Retain one existing path/hash/mode tool identity with its physical size."""
    require(type(source) is dict and set(source) == {"path", "sha256", "mode"},
            f"ordinary-link {role} source tool identity differs")
    path = source.get("path")
    require(type(path) is str and Path(path).is_absolute(), f"ordinary-link {role} source tool path differs")
    try:
        snapshot = inventory._snapshot_regular(work, Path(path), f"inputs/tools/{role}", path)
    except inventory.InventoryError as error:
        raise PublicDataEvidenceError(f"cannot retain ordinary-link {role} tool: {error}") from error
    original = snapshot["original"]
    require(all(original[key] == source[key] for key in source),
            f"ordinary-link {role} source tool changed during capture")
    retained_path = work / "inputs/tools" / role
    retained_path.chmod(retained_path.stat().st_mode | 0o444)
    snapshot["retained"] = inventory.file_record(retained_path, logical_path=f"inputs/tools/{role}")
    require(snapshot["retained"]["sha256"] == original["sha256"]
            and snapshot["retained"]["size"] == original["size"],
            f"ordinary-link {role} retained tool differs")
    return snapshot


def capture_tool_roster(root: Path, output: Path, static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    """Copy the exact native command tools before the first observed command.

    Installed drivers are not enough to identify the source compiler and LLD
    selected through their installed helper.  The existing wordexp reader
    resolves that constrained pair; this component retains every resolved
    executable byte for host-side replay without running it again.
    """
    try:
        installed = wordexp._installed_tool_roster(dynamic_product, static_product)
        sources = {
            "static_driver": installed["static-driver"],
            "dynamic_driver": installed["dynamic-driver"],
            "compiler": installed["compiler"],
            "linker": installed["linker"],
            "oracle_wrapper": fixed_image_tool_identity(Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl compiler wrapper"),
            "env": fixed_image_tool_identity(Path("/usr/bin/env"), "environment reset tool"),
            "readelf": fixed_image_tool_identity(inventory.TOOL_PATHS["readelf"], "ELF reader"),
            "chroot": installed["chroot"],
        }
        require(set(sources) == set(TOOL_ROLES), "ordinary-link native tool roster differs")
        result = {}
        for role in TOOL_ROLES:
            source = sources[role]
            result[role] = retain_tool_snapshot(output, role, source)
        return result
    except (wordexp.EvidenceError, inventory.InventoryError, OSError, ValueError) as error:
        raise PublicDataEvidenceError(f"cannot seal ordinary-link native tools: {error}") from error


def capture_oracle_static_inputs(work: Path, paths: Mapping[str, Path] = ORACLE_STATIC_INPUTS) -> dict[str, Any]:
    """Retain the precise musl archive and CRT inputs selected by static link."""
    require(set(paths) == set(ORACLE_STATIC_INPUTS), "ordinary-link oracle static input roster differs")
    result = {}
    try:
        for name in ORACLE_STATIC_INPUTS:
            source = inventory.physical_regular(Path(paths[name]), "oracle static " + name)
            snapshot = inventory._snapshot_regular(work, source, f"inputs/oracle-static/{name}", str(source))
            retained_path = work / "inputs/oracle-static" / name
            retained_path.chmod(retained_path.stat().st_mode | 0o444)
            snapshot["retained"] = inventory.file_record(retained_path, logical_path=f"inputs/oracle-static/{name}")
            require(snapshot["retained"]["sha256"] == snapshot["original"]["sha256"]
                    and snapshot["retained"]["size"] == snapshot["original"]["size"],
                    f"ordinary-link retained oracle static {name} differs")
            result[name] = snapshot
        return result
    except inventory.InventoryError as error:
        raise PublicDataEvidenceError(f"cannot seal oracle static inputs: {error}") from error


def validate_oracle_static_inputs(work: Path, record: object) -> dict[str, Any]:
    require(type(record) is dict and set(record) == set(ORACLE_STATIC_INPUTS),
            "ordinary-link oracle static input roster differs")
    try:
        for name in ORACLE_STATIC_INPUTS:
            inventory._validate_snapshot(
                work, record[name], "ordinary-link oracle static " + name,
                expected_original_path=str(ORACLE_STATIC_INPUTS[name]),
                expected_retained_path=f"inputs/oracle-static/{name}",
            )
    except inventory.InventoryError as error:
        raise PublicDataEvidenceError(f"ordinary-link oracle static replay failed: {error}") from error
    return record


def require_live_oracle_static_inputs(record: Mapping[str, Any]) -> None:
    """Collection-only before/after check; retained replay never reads `/opt`."""
    for name in ORACLE_STATIC_INPUTS:
        original = record[name]["original"]
        try:
            current = inventory.file_record(Path(original["path"]), logical_path=original["path"])
        except inventory.InventoryError as error:
            raise PublicDataEvidenceError(f"oracle static {name} disappeared during collection") from error
        require(current == original, f"oracle static {name} changed during collection")


def validate_tool_roster(root: Path, work: Path, inputs: Mapping[str, Any], tools: object) -> dict[str, Any]:
    require(type(tools) is dict and set(tools) == set(TOOL_ROLES), "ordinary-link native tool roster differs")
    static_product = root / inputs["static_preparation"]["primary"]["path"]
    dynamic_product = root / inputs["dynamic_product"]["path"]
    expected_original = {
        "static_driver": mounted(root, static_product / "bin/crabc-cc"),
        "dynamic_driver": mounted(root, dynamic_product / "bin/crabc-cc-dynamic"),
        "oracle_wrapper": "/usr/local/bin/crabc-x86_64-musl-gcc",
        "env": "/usr/bin/env",
        "readelf": str(inventory.TOOL_PATHS["readelf"]),
    }
    result = {}
    try:
        for role in TOOL_ROLES:
            record = tools[role]
            inventory._validate_snapshot(
                work,
                record,
                "ordinary-link " + role + " tool",
                expected_original_path=expected_original.get(role),
                expected_retained_path=f"inputs/tools/{role}",
            )
            result[role] = record
    except inventory.InventoryError as error:
        raise PublicDataEvidenceError(f"ordinary-link native tool replay failed: {error}") from error
    oracle = result["oracle_wrapper"]["original"]
    require(oracle["path"] == "/usr/local/bin/crabc-x86_64-musl-gcc",
            "ordinary-link oracle compiler path differs")
    return result


def require_live_tool_roster(tools: Mapping[str, Any]) -> None:
    """Collection-only before/after seal; host replay uses retained copies."""
    for role in TOOL_ROLES:
        record = tools[role]
        require(type(record) is dict and type(record.get("original")) is dict,
                f"ordinary-link {role} tool record differs")
        original = record["original"]
        try:
            current = inventory.file_record(Path(original["path"]), logical_path=original["path"])
        except inventory.InventoryError as error:
            raise PublicDataEvidenceError(f"ordinary-link {role} tool disappeared during collection") from error
        require(current == original, f"ordinary-link {role} tool changed during collection")


def execution_tree(root: Path, directory: Path, description: str) -> dict[str, dict[str, Any]]:
    """Describe one contained execution root without following aliases."""
    directory = physical_work_path(root, directory, description)
    require(directory.is_dir() and not directory.is_symlink(), f"{description} is not a physical directory")
    entries: dict[str, dict[str, Any]] = {}
    try:
        paths = sorted(directory.rglob("*"), key=lambda item: item.as_posix())
    except OSError as error:
        raise PublicDataEvidenceError(f"cannot enumerate {description}: {error}") from error
    for path in paths:
        relative = path.relative_to(directory).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            entry = {"kind": "directory", "mode": mode}
        elif stat.S_ISREG(metadata.st_mode):
            entry = {"kind": "file", "mode": mode, "size": metadata.st_size, "sha256": digest(path)}
        elif stat.S_ISLNK(metadata.st_mode):
            entry = {"kind": "symlink", "mode": mode, "target": os.readlink(path)}
        else:
            raise PublicDataEvidenceError(f"{description} has unsupported node: {relative}")
        entries[relative] = entry
    return entries


def readable_tree(entries: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Predict the retention finalizer's additive permission change."""
    result = {}
    for relative, entry in entries.items():
        current = dict(entry)
        if current["kind"] == "directory":
            current["mode"] |= 0o555
        elif current["kind"] == "file":
            current["mode"] |= 0o444
        result[relative] = current
    return result


def execution_copy(root: Path, source: Path, copied: Path, description: str) -> dict[str, Any]:
    source_identity = work_file_identity(root, source, description + " source")
    copy_identity = work_file_identity(root, copied, description + " execution copy")
    require(source_identity["sha256"] == copy_identity["sha256"] and source_identity["size"] == copy_identity["size"],
            description + " bytes differ")
    return {"source": source_identity, "copy": copy_identity}


def executable_observations(root: Path, work: Path) -> dict[str, Any]:
    """Reopen all seven retained executables and parse their recorded ELF views."""
    work = physical_work_path(root, work, "ordinary-link work")
    result = {}
    for name, expected in EXECUTABLE_ELF_MODES.items():
        executable = work_file_identity(root, work / name, name + " executable")
        try:
            header = raw_path(work, name + "-header", "stdout").read_text(encoding="utf-8")
            program = raw_path(work, name + "-program", "stdout").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise PublicDataEvidenceError(f"cannot read retained {name} ELF view: {error}") from error
        require(re.search(r"^\s*Class:\s+ELF64\s*$", header, re.MULTILINE) is not None
                and re.search(r"^\s*Data:\s+2's complement, little endian\s*$", header, re.MULTILINE) is not None
                and re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", header, re.MULTILINE) is not None,
                name + " ELF target differs")
        require(re.search(r"^\s*Type:\s+" + expected["type"] + r"(?:\s|\()", header, re.MULTILINE) is not None,
                name + " ELF type differs")
        interpreter = expected["interpreter"]
        if interpreter is None:
            require("Requesting program interpreter:" not in program and re.search(r"^\s*INTERP\b", program, re.MULTILINE) is None,
                    name + " ELF unexpectedly has an interpreter")
        else:
            require(program.count("Requesting program interpreter: " + interpreter) == 1,
                    name + " ELF interpreter differs")
        result[name] = {"executable": executable, "elf": dict(expected)}
    return result


def validate_executable_observations(root: Path, work: Path, record: object) -> dict[str, Any]:
    require(type(record) is dict and set(record) == set(EXECUTABLE_ELF_MODES),
            "ordinary-link executable roster differs")
    actual = executable_observations(root, work)
    require(same_json(record, actual), "ordinary-link executable ELF observations differ")
    return actual


def capture_execution_roots(root: Path, work: Path, dynamic_product: Path) -> dict[str, Any]:
    """Seal each chroot payload, interpreter, and copied consumer exactly once."""
    work = physical_work_path(root, work, "ordinary-link work")
    dynamic_product = physical_work_path(root, dynamic_product, "dynamic product")
    candidate_root = work / "candidate-root"
    oracle_root = work / "oracle-root"
    candidate_source = execution_tree(root, dynamic_product, "candidate dynamic product")
    static_products.make_retained_evidence_readable(candidate_root)
    static_products.make_retained_evidence_readable(oracle_root)
    candidate_tree = execution_tree(root, candidate_root, "candidate execution root")
    oracle_tree = execution_tree(root, oracle_root, "oracle execution root")
    candidate_consumers = {
        mode: execution_copy(root, work / ("dynamic-" + mode), candidate_root / ("consumer-" + mode),
                             "candidate " + mode + " consumer")
        for mode in ("pie", "non-pie")
    }
    oracle_consumers = {
        mode: execution_copy(root, work / ("oracle-dynamic-" + mode), oracle_root / ("consumer-" + mode),
                             "oracle " + mode + " consumer")
        for mode in ("pie", "non-pie")
    }
    return {
        "candidate": {
            "root": "candidate-root", "source_tree": candidate_source, "tree": candidate_tree,
            "consumers": candidate_consumers,
        },
        "oracle": {
            "root": "oracle-root", "runtime": work_file_identity(
                root, work / "qualification-oracle/runtime", "retained oracle runtime"
            ), "tree": oracle_tree, "consumers": oracle_consumers,
        },
    }


def validate_execution_roots(root: Path, work: Path, dynamic_product: Path, record: object) -> dict[str, Any]:
    """Reopen every copied execution payload; no root is trusted by its path."""
    require(type(record) is dict and set(record) == {"candidate", "oracle"},
            "ordinary-link execution root roster differs")
    work = physical_work_path(root, work, "ordinary-link work")
    dynamic_product = physical_work_path(root, dynamic_product, "dynamic product")
    candidate = record["candidate"]
    oracle = record["oracle"]
    require(type(candidate) is dict and set(candidate) == {"root", "source_tree", "tree", "consumers"},
            "candidate execution root fields differ")
    require(candidate["root"] == "candidate-root", "candidate execution root path differs")
    current_source = execution_tree(root, dynamic_product, "candidate dynamic product")
    current_tree = execution_tree(root, work / candidate["root"], "candidate execution root")
    require(same_json(candidate["source_tree"], current_source) and same_json(candidate["tree"], current_tree),
            "candidate execution root bytes or roster differ")
    consumers = candidate["consumers"]
    require(type(consumers) is dict and set(consumers) == {"pie", "non-pie"},
            "candidate execution consumer roster differs")
    allowed = set(current_source) | {"consumer-pie", "consumer-non-pie"}
    require(set(current_tree) == allowed, "candidate execution root contains undeclared payload")
    for relative, entry in readable_tree(current_source).items():
        require(current_tree[relative] == entry, "candidate execution root product copy differs")
    for mode in ("pie", "non-pie"):
        current = execution_copy(root, work / ("dynamic-" + mode), work / candidate["root"] / ("consumer-" + mode),
                                 "candidate " + mode + " consumer")
        require(same_json(consumers[mode], current), "candidate execution consumer differs")
        require(current_tree["consumer-" + mode]["kind"] == "file"
                and current_tree["consumer-" + mode]["sha256"] == current["copy"]["sha256"],
                "candidate execution consumer tree differs")
    require(type(oracle) is dict and set(oracle) == {"root", "runtime", "tree", "consumers"},
            "oracle execution root fields differ")
    require(oracle["root"] == "oracle-root", "oracle execution root path differs")
    runtime = resolve_work_identity(root, oracle["runtime"], "retained oracle runtime")
    require(runtime == work / "qualification-oracle/runtime", "oracle runtime path differs")
    oracle_tree = execution_tree(root, work / oracle["root"], "oracle execution root")
    require(same_json(oracle["tree"], oracle_tree), "oracle execution root bytes or roster differ")
    expected_oracle_entries = {"lib", "lib/ld-musl-x86_64.so.1", "lib/libc.so", "consumer-pie", "consumer-non-pie"}
    require(set(oracle_tree) == expected_oracle_entries, "oracle execution root contains undeclared payload")
    interpreter = oracle_tree["lib/ld-musl-x86_64.so.1"]
    require(interpreter["kind"] == "file" and interpreter["sha256"] == digest(runtime),
            "oracle execution interpreter differs from retained runtime")
    require(oracle_tree["lib/libc.so"] == {"kind": "symlink", "mode": oracle_tree["lib/libc.so"]["mode"],
                                             "target": "ld-musl-x86_64.so.1"},
            "oracle execution libc alias differs")
    oracle_consumers = oracle["consumers"]
    require(type(oracle_consumers) is dict and set(oracle_consumers) == {"pie", "non-pie"},
            "oracle execution consumer roster differs")
    for mode in ("pie", "non-pie"):
        current = execution_copy(root, work / ("oracle-dynamic-" + mode), work / oracle["root"] / ("consumer-" + mode),
                                 "oracle " + mode + " consumer")
        require(same_json(oracle_consumers[mode], current), "oracle execution consumer differs")
        require(oracle_tree["consumer-" + mode]["kind"] == "file"
                and oracle_tree["consumer-" + mode]["sha256"] == current["copy"]["sha256"],
                "oracle execution consumer tree differs")
    return record


class Collector:
    def __init__(self, root: Path, output: Path, static_preparation: Path,
                 static_product: Path, dynamic_product: Path) -> None:
        self.root = Path(root).absolute()
        self.output = output
        self.static_preparation = static_preparation
        self.static_product = static_product
        self.dynamic_product = dynamic_product
        self.commands: list[dict[str, Any]] = []

    @staticmethod
    def _terminate_owned_group(process: subprocess.Popen[bytes]) -> int:
        """Terminate the new-session command and every ordinary descendant.

        This is the same process-group boundary used by the owned static
        consumer matrix.  Retaining a timeout after only killing the leader
        would let a child escape into later evidence commands.
        """
        group = process.pid
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
        while consumer_matrix.group_has_live_members(group) and time.monotonic() < deadline:
            time.sleep(consumer_matrix.POLL_SECONDS)
        if consumer_matrix.group_has_live_members(group):
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            return process.wait(timeout=TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait()

    def run(self, label: str, command: list[str], *, stdout: bytes | None = None,
            cwd: Path | None = None, timeout_seconds: float = COMMAND_TIMEOUT_SECONDS) -> dict[str, Any]:
        raw = self.output / "raw"
        raw.mkdir(exist_ok=True)
        command_path = raw_path(self.output, label, "command.json")
        stdout_path = raw_path(self.output, label, "stdout")
        stderr_path = raw_path(self.output, label, "stderr")
        status_path = raw_path(self.output, label, "status")
        write_new_json(command_path, command)
        working_directory = self.root if cwd is None else Path(cwd)
        require(working_directory in {self.root, self.output}, "ordinary-link command cwd differs")
        require(type(timeout_seconds) in {int, float} and timeout_seconds > 0,
                "ordinary-link command timeout differs")
        outcome = "failed"
        status = 127
        with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
            try:
                process = subprocess.Popen(command, cwd=working_directory, stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err, start_new_session=True)
                try:
                    status = process.wait(timeout=timeout_seconds)
                    outcome = "ok" if status == 0 else "failed"
                except subprocess.TimeoutExpired:
                    status = self._terminate_owned_group(process)
                    outcome = "timed-out"
            except OSError as error:
                err.write((str(error) + "\n").encode())
        status_payload = f"{status}\n" if outcome != "timed-out" else f"timed-out:{status}\n"
        status_path.write_text(status_payload, encoding="ascii")
        row = {
            "label": label, "argv": command, "cwd": mounted(self.root, working_directory), "outcome": outcome,
            "command": work_file_identity(self.root, command_path, label + " command"),
            "stdout": work_file_identity(self.root, stdout_path, label + " stdout"),
            "stderr": work_file_identity(self.root, stderr_path, label + " stderr"),
            "status": work_file_identity(self.root, status_path, label + " status"),
        }
        self.commands.append(row)
        require(outcome != "timed-out", f"ordinary-link command timed out: {label}")
        require(status == 0, f"ordinary-link command failed: {label}")
        if stdout is not None:
            require(stdout_path.read_bytes() == stdout and stderr_path.read_bytes() == b"",
                    f"ordinary-link execution output differs: {label}")
        return row

    def link_receipt(self, mode: str) -> Path:
        suffix = ".crabc-link.json"
        return self.output / (mode + suffix)

    def collect(self) -> dict[str, Any]:
        image = os.environ.get(IMAGE_ENV, "")
        require(IMAGE_PATTERN.fullmatch(image) is not None,
                f"dispatcher must supply {IMAGE_ENV} as a resolved crabc-core-evidence digest")
        self.output.mkdir()
        before = admit_inputs(self.root, self.static_preparation, self.static_product, self.dynamic_product)
        policy = selection_identity(self.root)
        oracle = qualification.capture_oracle(self.output)
        qualification.validate_oracle(self.output, oracle)
        oracle_static_inputs = capture_oracle_static_inputs(self.output)
        tools = capture_tool_roster(self.root, self.output, self.static_product, self.dynamic_product)
        probe = self.output / "public_data_ordinary_link_probe.c"
        shutil.copy2(PROBE, probe)
        probe_source = work_file_identity(self.root, probe, "retained ordinary-link probe")
        object_path = self.output / "probe.o"
        self.run("compile", [tools["dynamic_driver"]["original"]["path"], "--dynamic-pie", "-std=c11", "-fno-builtin",
                             "-fno-stack-protector", "-c", str(probe), "-o", str(object_path)])
        readelf = tools["readelf"]["original"]["path"]
        self.run("object-symbols", [readelf, "-sW", str(object_path)])
        oracle_cc = tools["oracle_wrapper"]["original"]["path"]
        self.run("oracle-static-link", [oracle_cc, "-static", "-no-pie", str(object_path),
                                        "-o", str(self.output / "oracle-static")])
        for mode in STATIC_MODES:
            receipt = self.link_receipt(mode)
            self.run(mode + "-link", [tools["static_driver"]["original"]["path"], "-" + mode, "--link-receipt",
                                      receipt.name, str(object_path), "-o", str(self.output / mode)],
                     cwd=self.output)
        for mode in ("pie", "non-pie"):
            flags = ["-fPIE", "-pie"] if mode == "pie" else ["-no-pie"]
            self.run("oracle-dynamic-" + mode + "-link", [
                oracle_cc, *flags, str(object_path), "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1",
                "-o", str(self.output / ("oracle-dynamic-" + mode))
            ])
            self.run("dynamic-" + mode + "-link", [tools["dynamic_driver"]["original"]["path"], "--dynamic-" + mode,
                                                   str(object_path), "-o",
                                                   str(self.output / ("dynamic-" + mode))])
        for name in ALL_EXECUTABLES:
            binary = self.output / name
            for option, suffix in (("-hW", "header"), ("-lW", "program"), ("-sW", "symbols"), ("-rW", "relocations")):
                self.run(name + "-" + suffix, [readelf, option, str(binary)])
        for name in ("oracle-static", "static", "static-pie"):
            self.run(name + "-run", [tools["env"]["original"]["path"], "-i", str(self.output / name)], stdout=EXPECTED_STDOUT)
        oracle_root = self.output / "oracle-root"
        (oracle_root / "lib").mkdir(parents=True)
        shutil.copy2(self.output / "qualification-oracle/runtime", oracle_root / "lib/ld-musl-x86_64.so.1")
        (oracle_root / "lib/libc.so").symlink_to("ld-musl-x86_64.so.1")
        candidate_root = self.output / "candidate-root"
        shutil.copytree(self.dynamic_product, candidate_root, symlinks=True)
        for owner, execution_root, interpreter in (
            ("oracle", oracle_root, "/lib/ld-musl-x86_64.so.1"),
            ("candidate", candidate_root, "/lib/ld-crabc-x86_64.so.1"),
        ):
            for mode in ("pie", "non-pie"):
                binary = self.output / (("oracle-dynamic-" if owner == "oracle" else "dynamic-") + mode)
                consumer = execution_root / ("consumer-" + mode)
                shutil.copy2(binary, consumer)
                for entry in ("kernel", "direct"):
                    command = [tools["env"]["original"]["path"], "-i",
                               tools["chroot"]["original"]["path"], str(execution_root)]
                    if entry == "direct":
                        command.append(interpreter)
                    command.append("/consumer-" + mode)
                    label = ("oracle-dynamic-" if owner == "oracle" else "dynamic-") + mode + "-" + entry
                    self.run(label, command, stdout=EXPECTED_STDOUT)
        execution_roots = capture_execution_roots(self.root, self.output, self.dynamic_product)
        after = admit_inputs(self.root, self.static_preparation, self.static_product, self.dynamic_product)
        require(same_json(before, after), "supplied source or products changed during ordinary-link collection")
        require_live_tool_roster(tools)
        require_live_oracle_static_inputs(oracle_static_inputs)
        observations = observe(self.root, self.output, policy)
        executables = executable_observations(self.root, self.output)
        links = candidate_links(self.root, self.output, before, tools)
        return {
            "schema": SCHEMA,
            "status": "ordinary-link-evidence-unqualified",
            "target": "x86_64-unknown-linux-musl",
            "image": image,
            "source_before": before,
            "source_after": after,
            "selection": policy,
            "probe": {
                "source": probe_source,
                "object": work_file_identity(self.root, object_path, "ordinary-link object"),
            },
            "oracle": oracle,
            "oracle_static_inputs": oracle_static_inputs,
            "tools": tools,
            "execution_roots": execution_roots,
            "commands": self.commands,
            "executables": executables,
            "observations": observations,
            "links": links,
            "limits": [
                "No lifecycle, strong-override, interposition, COPY-relocation, or header-feature-profile proof.",
                "Shared-only _dl_debug_addr remains owned by the loader debugger component.",
                "Prepared/materialized ordinary-link evidence is not runtime qualification, family completion, or public support.",
            ],
        }


def rows_for(work: Path, label: str) -> list[dict[str, Any]]:
    path = raw_path(work, label, "stdout")
    tables = inventory.parse_elf_symbol_tables(path.read_text(encoding="utf-8"))
    matching = [table for table in tables if table["name"] == ".symtab"]
    require(len(matching) == 1, f"{label} lacks exactly one .symtab")
    return matching[0]["rows"]


def reduced_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in ("name", "type", "binding", "visibility", "version",
                                       "version_default", "section_index", "value", "size_bytes")}


def observe(root: Path, work: Path, policy: Mapping[str, Any]) -> dict[str, Any]:
    names = policy["names"]
    aliases = policy["aliases"]
    object_rows = rows_for(work, "object-symbols")
    undefined = [row for row in object_rows if row["section_index"] == "UND" and row["name"]]
    require({row["name"] for row in undefined} == set(names) | {"write"},
            "ordinary-link probe undefined object set differs")
    for row in undefined:
        require((row["type"], row["binding"], row["visibility"], row["version"], row["version_default"]) ==
                ("NOTYPE", "GLOBAL", "DEFAULT", None, False),
                "ordinary-link probe import metadata differs")
    contracts = {item["name"]: item for item in selected_objects()[0]}
    definitions: dict[str, dict[str, dict[str, Any]]] = {}
    aliases_observed: dict[str, dict[str, dict[str, Any]]] = {}
    for mode in STATIC_MODES:
        rows = rows_for(work, mode + "-symbols")
        current: dict[str, dict[str, Any]] = {}
        for name in names:
            matches = [row for row in rows if row["name"] == name]
            require(len(matches) == 1, f"{mode} has missing or duplicate selected definition: {name}")
            row = matches[0]
            contract = contracts[name]
            require(row["section_index"].isdigit(), f"{mode} selected object is not defined: {name}")
            for key in ("type", "binding", "visibility"):
                require(row[key] == contract[key], f"{mode} selected object metadata differs: {name}/{key}")
            require(row["version"] is None and row["version_default"] is False,
                    f"{mode} selected object version differs: {name}")
            require(row["size_bytes"] == contract["size_bytes"], f"{mode} selected object size differs: {name}")
            require(int(row["value"], 16) % contract["alignment_bytes"] == 0,
                    f"{mode} selected object alignment differs: {name}")
            current[name] = reduced_row(row)
        definitions[mode] = current
        alias_rows: dict[str, dict[str, Any]] = {}
        for alias in aliases:
            row, target = current[alias["name"]], current[alias["target"]]
            require(tuple(row[key] for key in ("section_index", "value", "type", "size_bytes")) ==
                    tuple(target[key] for key in ("section_index", "value", "type", "size_bytes")),
                    f"{mode} source-declared alias does not share static storage: {alias['name']}")
            alias_rows[alias["name"]] = {
                "target": alias["target"], "section_index": row["section_index"], "value": row["value"],
                "type": row["type"], "size_bytes": row["size_bytes"],
            }
        aliases_observed[mode] = alias_rows
    return {
        "imports": [reduced_row(row) for row in undefined],
        "static_definitions": definitions,
        "static_aliases": aliases_observed,
    }


def candidate_links(root: Path, work: Path, inputs: Mapping[str, Any], tools: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    static_product = root / inputs["static_preparation"]["primary"]["path"]
    dynamic_product = root / inputs["dynamic_product"]["path"]
    result: dict[str, dict[str, Any]] = {}
    for mode in CANDIDATE_MODES:
        linkage = {"static": "static", "static-pie": "static-pie",
                   "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}[mode]
        receipt = work / (mode + ".crabc-link.json")
        if mode in STATIC_MODES:
            receipt = work / (mode + ".crabc-link.json")
        record = read_json(receipt, mode + " link receipt")
        linker = record.get("resolved_linker")
        sealed = tools.get("linker")
        require(type(sealed) is dict and type(sealed.get("original")) is dict,
                "ordinary-link independent linker roster differs")
        expected_linker = {
            "path": sealed["original"].get("path"),
            "sha256": sealed["original"].get("sha256"),
        }
        require(type(linker) is dict and linker == expected_linker,
                f"{mode} link receipt selected an unsealed linker")
        result[mode] = {
            "linkage": linkage,
            "product": "static" if mode in STATIC_MODES else "dynamic",
            "receipt": work_file_identity(root, receipt, mode + " link receipt"),
            "executable": work_file_identity(root, work / mode, mode + " executable"),
            "linker": expected_linker,
            "product_manifest": (inputs["static_preparation"]["primary"]["manifest"]
                                 if mode in STATIC_MODES else inputs["dynamic_product"]["manifest"]),
        }
    return result


def expected_command_labels() -> tuple[str, ...]:
    labels = ["compile", "object-symbols", "oracle-static-link", "static-link", "static-pie-link"]
    for mode in ("pie", "non-pie"):
        labels.extend(("oracle-dynamic-" + mode + "-link", "dynamic-" + mode + "-link"))
    for name in ALL_EXECUTABLES:
        labels.extend((name + "-header", name + "-program", name + "-symbols", name + "-relocations"))
    labels.extend(EXECUTION_LABELS)
    return tuple(labels)


def expected_commands(root: Path, work: Path, inputs: Mapping[str, Any],
                      tools: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    static_product = root / inputs["static_preparation"]["primary"]["path"]
    dynamic_product = root / inputs["dynamic_product"]["path"]
    def tool_path(name: str) -> str:
        record = tools.get(name)
        require(type(record) is dict and type(record.get("original")) is dict,
                f"ordinary-link {name} tool record differs")
        path = record["original"].get("path")
        require(type(path) is str and Path(path).is_absolute() and ".." not in Path(path).parts,
                f"ordinary-link {name} tool path differs")
        return path
    static_driver = tool_path("static_driver")
    dynamic_driver = tool_path("dynamic_driver")
    oracle_wrapper = tool_path("oracle_wrapper")
    env = tool_path("env")
    readelf = tool_path("readelf")
    chroot = tool_path("chroot")
    object_path = mounted(root, work / "probe.o")
    output = lambda name: mounted(root, work / name)
    result: dict[str, dict[str, Any]] = {
        "compile": {"cwd": SOURCE_MOUNT, "argv": [
            dynamic_driver, "--dynamic-pie", "-std=c11", "-fno-builtin", "-fno-stack-protector",
            "-c", output("public_data_ordinary_link_probe.c"), "-o", output("probe.o"),
        ]},
        "object-symbols": {"cwd": SOURCE_MOUNT, "argv": [readelf, "-sW", output("probe.o")]},
        "oracle-static-link": {"cwd": SOURCE_MOUNT, "argv": [
            oracle_wrapper, "-static", "-no-pie", object_path,
            "-o", output("oracle-static"),
        ]},
        "static-link": {"cwd": output(""), "argv": [
            static_driver, "-static", "--link-receipt", "static.crabc-link.json", object_path,
            "-o", output("static"),
        ]},
        "static-pie-link": {"cwd": output(""), "argv": [
            static_driver, "-static-pie", "--link-receipt", "static-pie.crabc-link.json", object_path,
            "-o", output("static-pie"),
        ]},
    }
    for mode in ("pie", "non-pie"):
        flags = ["-fPIE", "-pie"] if mode == "pie" else ["-no-pie"]
        result["oracle-dynamic-" + mode + "-link"] = {"cwd": SOURCE_MOUNT, "argv": [
            oracle_wrapper, *flags, object_path,
            "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1", "-o", output("oracle-dynamic-" + mode),
        ]}
        result["dynamic-" + mode + "-link"] = {"cwd": SOURCE_MOUNT, "argv": [
            dynamic_driver, "--dynamic-" + mode, object_path, "-o", output("dynamic-" + mode),
        ]}
    for name in ALL_EXECUTABLES:
        for option, suffix in (("-hW", "header"), ("-lW", "program"), ("-sW", "symbols"), ("-rW", "relocations")):
            result[name + "-" + suffix] = {"cwd": SOURCE_MOUNT, "argv": [readelf, option, output(name)]}
    for name in ("oracle-static", "static", "static-pie"):
        result[name + "-run"] = {"cwd": SOURCE_MOUNT, "argv": [env, "-i", output(name)]}
    for owner, root_name, interpreter in (
        ("oracle", "oracle-root", "/lib/ld-musl-x86_64.so.1"),
        ("candidate", "candidate-root", "/lib/ld-crabc-x86_64.so.1"),
    ):
        for mode in ("pie", "non-pie"):
            for entry in ("kernel", "direct"):
                argv = [env, "-i", chroot, output(root_name)]
                if entry == "direct":
                    argv.append(interpreter)
                argv.append("/consumer-" + mode)
                label = (("oracle-dynamic-" if owner == "oracle" else "dynamic-") + mode + "-" + entry)
                result[label] = {"cwd": SOURCE_MOUNT, "argv": argv}
    require(tuple(result) == expected_command_labels(), "ordinary-link expected command roster differs")
    return result


def validate_command_records(root: Path, work: Path, inputs: Mapping[str, Any], tools: Mapping[str, Any],
                             commands: object) -> None:
    require(type(commands) is list and [item.get("label") if type(item) is dict else None for item in commands]
            == list(expected_command_labels()), "ordinary-link command roster differs")
    expected = expected_commands(root, work, inputs, tools)
    for record in commands:
        require(set(record) == {"label", "argv", "cwd", "outcome", "command", "stdout", "stderr", "status"},
                "ordinary-link command record fields differ")
        require(type(record["argv"]) is list and all(type(item) is str for item in record["argv"]),
                "ordinary-link command argv differs")
        require(same_json({"cwd": record["cwd"], "argv": record["argv"]}, expected[record["label"]]),
                "ordinary-link command differs")
        command_path = resolve_work_identity(root, record["command"], record["label"] + " command")
        require(read_json(command_path, record["label"] + " command", list) == record["argv"],
                "ordinary-link retained command differs")
        for field in ("stdout", "stderr", "status"):
            path = resolve_work_identity(root, record[field], record["label"] + " " + field)
            if field == "status":
                require(record["outcome"] == "ok" and path.read_bytes() == b"0\n",
                        "ordinary-link command status differs")
        if record["label"] in EXECUTION_LABELS:
            stdout = resolve_work_identity(root, record["stdout"], record["label"] + " stdout")
            stderr = resolve_work_identity(root, record["stderr"], record["label"] + " stderr")
            require(stdout.read_bytes() == EXPECTED_STDOUT and stderr.read_bytes() == b"",
                    "ordinary-link execution output differs")


def validate_oracle_identity(work: Path, oracle: object) -> None:
    require(type(oracle) is dict, "ordinary-link oracle identity differs")
    qualification.validate_oracle(work, oracle)


def validate_links(root: Path, work: Path, inputs: Mapping[str, Any], tools: Mapping[str, Any],
                   links: object) -> dict[str, Any]:
    require(type(links) is dict and set(links) == set(CANDIDATE_MODES),
            "ordinary-link candidate link roster differs")
    static_product = root / inputs["static_preparation"]["primary"]["path"]
    dynamic_product = root / inputs["dynamic_product"]["path"]
    linker_record = tools.get("linker") if type(tools) is dict else None
    require(type(linker_record) is dict and type(linker_record.get("original")) is dict,
            "ordinary-link independent linker roster differs")
    sealed_linker = {
        "path": linker_record["original"].get("path"),
        "sha256": linker_record["original"].get("sha256"),
    }
    result = {}
    for mode in CANDIDATE_MODES:
        record = links[mode]
        require(type(record) is dict and set(record) == {
            "linkage", "product", "receipt", "executable", "linker", "product_manifest"
        }, f"{mode} retained link fields differ")
        linkage = {"static": "static", "static-pie": "static-pie",
                   "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}[mode]
        static_mode = mode in STATIC_MODES
        require(record["linkage"] == linkage and record["product"] == ("static" if static_mode else "dynamic"),
                f"{mode} retained link mode differs")
        expected_receipt = work / (mode + ".crabc-link.json")
        receipt = resolve_work_identity(root, record["receipt"], mode + " retained receipt")
        executable = resolve_work_identity(root, record["executable"], mode + " retained executable")
        require(receipt == expected_receipt and executable == work / mode,
                f"{mode} retained link artifact path differs")
        expected_manifest = inputs["static_preparation"]["primary"]["manifest"] if static_mode else inputs["dynamic_product"]["manifest"]
        require(same_json(record["product_manifest"], expected_manifest), f"{mode} retained product manifest differs")
        require(record["linker"] == sealed_linker, f"{mode} retained linker differs from independent roster")
        result[mode] = products.validate_retained_link(
            root, SOURCE_MOUNT, static_product if static_mode else dynamic_product,
            work / "probe.o", executable, receipt, linkage, sealed_linker
        )
    return result


def validate_observations(root: Path, work: Path, policy: Mapping[str, Any], observations: object) -> dict[str, Any]:
    require(type(observations) is dict and set(observations) == {"imports", "static_definitions", "static_aliases"},
            "ordinary-link observation fields differ")
    actual = observe(root, work, policy)
    require(same_json(observations, actual), "ordinary-link ELF observations differ")
    return actual


def validate_report(root: Path, report_path: Path) -> dict[str, Any]:
    root = Path(root).absolute()
    report_path = physical_work_path(root, report_path, "ordinary-link report")
    require(report_path.name == "report.json", "ordinary-link report must be named report.json")
    report = read_json(report_path, "ordinary-link report")
    expected_keys = {
        "schema", "status", "target", "image", "source_before", "source_after", "selection", "probe",
        "oracle", "oracle_static_inputs", "tools", "execution_roots", "commands", "executables", "observations",
        "links", "limits",
    }
    require(set(report) == expected_keys, "ordinary-link report fields differ")
    require(report["schema"] == SCHEMA and report["status"] == "ordinary-link-evidence-unqualified"
            and report["target"] == "x86_64-unknown-linux-musl", "ordinary-link report boundary differs")
    require(IMAGE_PATTERN.fullmatch(report["image"]) is not None, "ordinary-link report image differs")
    work = report_path.parent
    before = report["source_before"]
    require(type(before) is dict and set(before) == {"source", "static_preparation", "dynamic_product"},
            "ordinary-link input identity differs")
    static_preparation = before["static_preparation"]
    dynamic = before["dynamic_product"]
    require(type(static_preparation) is dict and type(dynamic) is dict,
            "ordinary-link product identity fields differ")
    static_receipt = resolve_work_identity(root, static_preparation.get("receipt"),
                                            "retained static preparation")
    primary = static_preparation.get("primary")
    require(type(primary) is dict and type(primary.get("path")) is str and type(dynamic.get("path")) is str,
            "ordinary-link product identity paths differ")
    static_product = root / primary["path"]
    dynamic_product = root / dynamic["path"]
    actual_inputs = admit_inputs(root, static_receipt, static_product, dynamic_product)
    require(same_json(before, actual_inputs) and same_json(report["source_after"], actual_inputs),
            "ordinary-link source or product identity differs")
    policy = selection_identity(root)
    require(same_json(report["selection"], policy), "ordinary-link selection contract changed")
    require(type(report["probe"]) is dict and set(report["probe"]) == {"source", "object"},
            "ordinary-link probe fields differ")
    probe_source = resolve_work_identity(root, report["probe"]["source"], "retained ordinary-link probe")
    probe_object = resolve_work_identity(root, report["probe"]["object"], "ordinary-link object")
    require(probe_source == work / "public_data_ordinary_link_probe.c" and probe_object == work / "probe.o",
            "ordinary-link probe path differs")
    require(digest(probe_source) == digest(PROBE), "retained ordinary-link probe source differs")
    validate_oracle_identity(work, report["oracle"])
    validate_oracle_static_inputs(work, report["oracle_static_inputs"])
    tools = validate_tool_roster(root, work, actual_inputs, report["tools"])
    require(tools["oracle_wrapper"]["original"]["sha256"] == report["oracle"]["compiler_wrapper_sha256"],
            "ordinary-link oracle compiler differs from retained oracle")
    validate_command_records(root, work, actual_inputs, tools, report["commands"])
    validate_executable_observations(root, work, report["executables"])
    validate_execution_roots(root, work, dynamic_product, report["execution_roots"])
    validate_observations(root, work, policy, report["observations"])
    links = validate_links(root, work, actual_inputs, tools, report["links"])
    require(report["limits"] == [
        "No lifecycle, strong-override, interposition, COPY-relocation, or header-feature-profile proof.",
        "Shared-only _dl_debug_addr remains owned by the loader debugger component.",
        "Prepared/materialized ordinary-link evidence is not runtime qualification, family completion, or public support.",
    ], "ordinary-link scope changed")
    return {"report": work_file_identity(root, report_path, "ordinary-link report"), "links": links}


def collect(root: Path, static_preparation: Path, static_product: Path,
            dynamic_product: Path, output: Path) -> Path:
    output = fresh_output(root, output)
    admit_output_disjoint(root, output, static_preparation, static_product, dynamic_product)
    collector = Collector(root, output, static_preparation, static_product, dynamic_product)
    try:
        record = collector.collect()
        write_new_json(output / "report.json", record)
        validate_report(root, output / "report.json")
    finally:
        if output.exists():
            static_products.make_retained_evidence_readable(output)
    return output / "report.json"


def parse_cli(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.allow_abbrev = False
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    collect_parser.allow_abbrev = False
    for name in ("static-preparation", "static-product", "dynamic-product", "output"):
        collect_parser.add_argument("--" + name, type=Path, action="append", required=True)
    validate_parser = commands.add_parser("validate-report")
    validate_parser.allow_abbrev = False
    validate_parser.add_argument("report", type=Path)
    args = parser.parse_args(arguments)
    if args.command == "collect":
        for name in ("static_preparation", "static_product", "dynamic_product", "output"):
            values = getattr(args, name)
            if len(values) != 1:
                parser.error("--" + name.replace("_", "-") + " must appear exactly once")
            setattr(args, name, values[0])
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    args = parse_cli()
    try:
        if args.command == "collect":
            print(collect(ROOT, args.static_preparation, args.static_product, args.dynamic_product, args.output))
        else:
            validate_report(ROOT, args.report)
            print("public-data ordinary-link receipt valid; runtime qualification and family closure remain independent")
    except (PublicDataEvidenceError, static_products.PreparationError, qualification.QualificationError,
            products.ProductEvidenceError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"public-data ordinary-link failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
