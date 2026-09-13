#!/usr/bin/env python3
"""Read and replay the finite owned pthread timed-feature receipt.

This reader deliberately owns one finite component contract.  It retains the
raw link commands, maps, objects, ELF/readelf streams, runtime transcripts,
and source/product inputs used by ``run_owned_pthread_timed_feature_contract.sh``.
It is not a general ELF collector and it does not infer any pthread-family or
platform-completion claim from the checked aliases.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Mapping, Sequence
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, NamedTuple

from owned_syscall_alias_authority import (RELOCATION_NAMES, archive_members, capture_git_objects, elf_bytes,
                                           require_symbol_stream, section_name, source_tree)
from owned_static_link_authority import (StaticFunctionContract, StaticLinkAuthorityError,
                                         require_static_functions)
import owned_posix_static_products as static_products
import owned_posix_product_evidence as product_evidence
from owned_pthread_timed_dynamic_authority import (
    PthreadTimedDynamicAuthorityError, require_pthread_timed_probe_functions,
)
from loader_debug_abi_evidence import Elf


SCHEMA = "crabc.x86_64-owned-pthread-timed-feature-contract/v1"
INPUT_SCHEMA = "owned-pthread-timed-feature-contract-inputs-v2"
SOURCE_SNAPSHOT_SCHEMA = "crabc.x86_64-owned-pthread-timed-feature-source-snapshot/v1"
STATUS = "component-verified"
COMPONENT = "pthread-timed-feature-alias-linkage"
MUSL_RELEASE = "musl-1.2.6"
MUSL_SOURCE_COMMIT = "9fa28ece75d8a2191de7c5bb53bed224c5947417"
SUCCESS_TRANSCRIPT = b"owned-pthread-timed-feature-contract-ok\n"
TIMEOUT_SECONDS = 45
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
ROOT = Path(__file__).resolve().parents[2]
PINNED_IMAGE = "sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
IMAGE_PATH = "/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
IMAGE_MANIFEST_PATH = ROOT / "compat/x86_64/owned_pthread_timed_feature_image_inputs.json"
# The runner, reader, oracle wrapper, and supplied drivers consume only this
# finite tool/image closure.  The checked-in manifest is validator authority;
# reports copy its records but cannot choose paths, modes, or digests.
IMAGE_COMMANDS = (
    "bash", "cat", "chmod", "chroot", "cmp", "cp", "dirname", "git", "grep",
    "mkdir", "mktemp", "python3", "readelf", "realpath", "timeout", "uname",
    "gcc", "as", "ld", "rustup",
)
IMAGE_FIXED_PATHS = (
    "/usr/local/bin/crabc-x86_64-musl-gcc",
    "/opt/musl-1.2.6/lib/libc.so",
    "/opt/musl-1.2.6/lib/libc.a",
    "/opt/musl-1.2.6/lib/musl-gcc.specs",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/bin/rustc",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld",
)
IMAGE_MANIFEST_SOURCE = "compat/x86_64/owned_pthread_timed_feature_image_inputs.json"
PREPARATION_RETAINED_ROOT = "retained/products/static-preparation"
EXECUTION_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": IMAGE_PATH,
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "TZ": "UTC",
}
EXECUTION_SCHEMA = "crabc.x86_64-owned-pthread-timed-feature-execution/v1"

# This is the entire source-shaped public alias roster.  The report has no
# extension hook: a later alias needs a separately reviewed component change.
ALIASES = (
    ("pthread_cond_timedwait", "__pthread_cond_timedwait"),
    ("pthread_mutex_timedlock", "__pthread_mutex_timedlock"),
    ("pthread_timedjoin_np", "__pthread_timedjoin_np"),
    ("pthread_tryjoin_np", "__pthread_tryjoin_np"),
)
ARCHIVE_HIDDEN = (
    "__pthread_cond_timedwait",
    "__pthread_mutex_timedlock",
    "__pthread_timedjoin_np",
    "__pthread_tryjoin_np",
)
ARCHIVE_LOCAL = ()
# musl keeps the GNU join implementation spellings local in libc.a, while its
# timed condition/mutex providers and all four selected crabc archive bodies
# are hidden. This is an archive-form distinction, not a public ABI difference.
MUSL_STATIC_PROVIDER_SHAPES = {
    "__pthread_cond_timedwait": ("FUNC", "GLOBAL", "HIDDEN"),
    "__pthread_mutex_timedlock": ("FUNC", "GLOBAL", "HIDDEN"),
    "__pthread_timedjoin_np": ("FUNC", "LOCAL", "DEFAULT"),
    "__pthread_tryjoin_np": ("FUNC", "LOCAL", "DEFAULT"),
}
CANDIDATE_STATIC_PROVIDER_SHAPES = {
    provider: ("FUNC", "GLOBAL", "HIDDEN") for provider in ARCHIVE_HIDDEN
}
FINAL_STATIC_PROVIDER_SHAPES = {
    provider: ("FUNC", "LOCAL", "HIDDEN") for provider in ARCHIVE_HIDDEN
}
PTHREAD_STATIC_MEMBER = "c.c.9c0a881dcc98e279-cgu.0.rcgu.o"
# These ten internal C helpers contain the actual bounded runtime observations;
# main only dispatches them. Their source and final bytes are separate static
# contracts so an unchanged main/provider map cannot discharge a replaced body.
PROBE_HELPERS = (
    "deadline_after",
    "wait_ready",
    "mutex_holder",
    "test_mutex_timedlock",
    "first_spurious_timedwait",
    "signaler",
    "test_condition_timedwait",
    "target",
    "cancelable_joiner",
    "test_join_modes",
)
# The raw archive observation includes retained DWARF section relocations as
# well as executable sections. This table only spells their readelf rendering;
# it does not broaden the shared static linker authority's accepted relocation
# forms for the four linked functions.
RAW_ARCHIVE_RELOCATION_NAMES = {
    **RELOCATION_NAMES,
    9: "R_X86_64_GOTPCREL",
    10: "R_X86_64_32",
    22: "R_X86_64_GOTTPOFF",
    42: "R_X86_64_REX_GOTPCRELX",
}
FEATURE = "x86-owned-static-runtime"
FEATURE_ALIASES = ALIASES

# These are the implementation leaves and source-policy caller that the
# receipt binds.  The full checkout digest is retained separately, so this
# compact roster is navigation for the checked component rather than a claim
# to select all pthread implementation source.
SOURCE_CONTRACT_PATHS = (
    "libc/Cargo.toml",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
    "libc/src/c_abi/x86_64/owned_pthread_cond.rs",
    "libc/src/c_abi/x86_64/pthread_cond.rs",
    "libc/src/c_abi/x86_64/pthread_create_join.rs",
    "libc/src/c_abi/x86_64/pthread_mutex.rs",
    "compat/x86_64/parity.toml",
    "scripts/build_x86_64_owned_sysroot.py",
)
COLLECTOR_PATHS = {
    "probe": "compat/x86_64/owned_pthread_timed_feature_contract_probe.c",
    "reader": "compat/x86_64/owned_pthread_timed_feature_contract_reader.py",
    "runner": "compat/x86_64/run_owned_pthread_timed_feature_contract.sh",
    "syscall_authority": "compat/x86_64/owned_syscall_alias_authority.py",
    "static_authority": "compat/x86_64/owned_static_link_authority.py",
    "elf_authority": "compat/x86_64/loader_debug_abi_evidence.py",
    "static_preparation_owner": "compat/x86_64/owned_posix_static_products.py",
    "static_package_owner": "compat/x86_64/owned_static_sysroot_package.py",
    "product_validator": "compat/x86_64/owned_posix_product_evidence.py",
    "dynamic_probe_authority": "compat/x86_64/owned_pthread_timed_dynamic_authority.py",
    "image_manifest": IMAGE_MANIFEST_SOURCE,
}
COLLECTOR_INPUTS = ("probe", "reader", "runner")
INPUT_NAMES = (
    "probe",
    "reader",
    "runner",
    "oracle_compiler",
    "musl_shared",
    "musl_archive",
    "static_driver",
    "static_libc",
    "static_crt1",
    "static_rcrt1",
    "static_crti",
    "static_crtn",
    "static_builtins",
    "dynamic_driver",
    "dynamic_crt1",
    "dynamic_scrt1",
    "dynamic_crti",
    "dynamic_crtn",
    "dynamic_attach",
    "dynamic_builtins",
    "dynamic_libc",
    "dynamic_loader",
    "product_report",
    "static_preparation",
)
HISTORICAL_INPUT_NAMES = (
    "dynamic_driver",
    "dynamic_libc",
    "musl_archive",
    "musl_shared",
    "probe",
    "reader",
    "runner",
    "static_driver",
    "static_libc",
)

COMMANDS = (
    "contract-compile",
    "oracle-link",
    "oracle",
    "static-link",
    "static",
    "static-pie-link",
    "static-pie",
    "musl-dynamic-pie-link",
    "musl-dynamic-pie-kernel",
    "musl-dynamic-pie-direct",
    "musl-dynamic-non-pie-link",
    "musl-dynamic-non-pie-kernel",
    "musl-dynamic-non-pie-direct",
    "dynamic-pie-link",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-link",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
LINK_OUTPUTS = {
    "oracle-link": "oracle-contract",
    "static-link": "static-contract",
    "static-pie-link": "static-pie-contract",
    "musl-dynamic-pie-link": "musl-dynamic-pie-contract",
    "musl-dynamic-non-pie-link": "musl-dynamic-non-pie-contract",
    "dynamic-pie-link": "dynamic-pie-contract",
    "dynamic-non-pie-link": "dynamic-non-pie-contract",
}
LINK_MAPS = {
    "oracle-link": "oracle-contract.map",
    "static-link": "static-contract.link.map",
    "static-pie-link": "static-pie-contract.link.map",
    "musl-dynamic-pie-link": "musl-dynamic-pie-contract.map",
    "musl-dynamic-non-pie-link": "musl-dynamic-non-pie-contract.map",
}
STATIC_LINK_RECEIPTS = (
    "static-contract.link.json",
    "static-pie-contract.link.json",
)
STATIC_LINK_TRACES = (
    "static-contract.link.trace",
    "static-pie-contract.link.trace",
)
RUNTIME_COMMANDS = tuple(
    name for name in COMMANDS if name not in {"contract-compile", *LINK_OUTPUTS}
)
ELF_TYPES = {
    "contract.o": "REL",
    "oracle-contract": "EXEC",
    "static-contract": "EXEC",
    "static-pie-contract": "DYN",
    "musl-dynamic-pie-contract": "DYN",
    "musl-dynamic-non-pie-contract": "EXEC",
    "dynamic-pie-contract": "DYN",
    "dynamic-non-pie-contract": "EXEC",
}
SYMBOL_STREAMS = (
    "musl-dynamic-symbols.txt",
    "candidate-dynamic-symbols.txt",
    "musl-shared-symbols.txt",
    "candidate-shared-symbols.txt",
    "musl-static-symbols.txt",
    "candidate-static-symbols.txt",
    "musl-static-relocations.txt",
    "candidate-static-relocations.txt",
    "static-contract.symbols.txt",
    "static-pie-contract.symbols.txt",
    "dynamic-pie-contract.symbols.txt",
    "dynamic-non-pie-contract.symbols.txt",
)
DYNAMIC_LINK_RECEIPTS = (
    "dynamic-pie-contract.crabc-link.json",
    "dynamic-non-pie-contract.crabc-link.json",
)
ROOT_TREES = (
    "musl-dynamic-pie-root",
    "musl-dynamic-non-pie-root",
    "dynamic-pie-root",
    "dynamic-non-pie-root",
)
DYNAMIC_STATE_FIELDS = {
    "schema", "status", "source_sha256", "contracts", "payload_files",
    "runtime_v1_published", "campaign_complete", "public_support", "modes",
    "runtime_profile", "qualification",
}
DYNAMIC_STATE_CONTRACTS = {
    "compat/x86_64/dynamic-product.toml",
    "compat/x86_64/loader-libc-tls-runtime-v1.toml",
}
DYNAMIC_STATE_PROFILE = (
    "retained dlclose mappings; default NOW with declared lazy imports; runtime GD growth; "
    "new runtime IE rejected"
)
DYNAMIC_STATE_QUALIFICATION = "separate live three-product receipt and review required"
DYNAMIC_STATE_MODES = ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"]
DYNAMIC_STATE_PATH = "share/crabc/dynamic-product-state.json"


class ReceiptError(ValueError):
    """The retained component receipt cannot establish its stated boundary."""


class SymbolRow(NamedTuple):
    member: str
    value: str
    symbol_type: str
    binding: str
    visibility: str
    section: str
    name: str


def same_definition(left: SymbolRow, right: SymbolRow) -> bool:
    """Return whether two symbols designate the same ELF function definition.

    ELF relocatable object symbols in different function sections commonly both
    have ``st_value == 0``.  Member/value/type alone can therefore turn a
    forwarding body into a false alias; section remains part of the identity.
    """

    return (
        left.member == right.member
        and left.value == right.value
        and left.symbol_type == right.symbol_type
        and left.section == right.section
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def _reject_constant(value: str) -> object:
    raise ReceiptError(f"invalid JSON constant {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _require_finite(value: object, location: str = "$") -> None:
    if isinstance(value, float):
        require(math.isfinite(value), f"non-finite JSON number at {location}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _require_finite(item, f"{location}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_finite(item, f"{location}.{key}")


def load_json(path: Path, label: str) -> object:
    """Read one raw receipt JSON file without lossy duplicate-key parsing."""

    require_regular(path, label)
    try:
        parsed = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as error:
        if isinstance(error, ReceiptError):
            raise
        raise ReceiptError(f"invalid {label} JSON: {error}") from error
    _require_finite(parsed)
    return parsed


def load_json_object(path: Path, label: str) -> dict[str, object]:
    parsed = load_json(path, label)
    require(isinstance(parsed, dict), f"{label} must be a JSON object")
    return parsed


def require_regular(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise ReceiptError(f"missing {label}: {path}") from error
    require(stat.S_ISREG(mode) and not stat.S_ISLNK(mode), f"unsafe {label}: {path}")


def sha256(path: Path) -> str:
    require_regular(path, "artifact")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: object, label: str) -> Path:
    require(isinstance(value, str) and value != "", f"{label} path must be nonempty text")
    path = Path(value)
    require(not path.is_absolute() and "." not in path.parts and ".." not in path.parts,
            f"unsafe {label} path: {value!r}")
    return path


def artifact_record(root: Path, path: Path) -> dict[str, object]:
    """Capture a regular receipt artifact relative to one receipt root."""

    root = root.resolve(strict=True)
    require_regular(path, "artifact")
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to(root), f"artifact outside receipt root: {path}")
    relative = resolved.relative_to(root).as_posix()
    return {"path": relative, "sha256": sha256(resolved), "size": resolved.stat().st_size, "mode": stat.S_IMODE(resolved.stat().st_mode)}


def validate_retained_artifact(root: Path, record: object, label: str) -> Path:
    """Require a retained artifact to keep its exact path, bytes and size."""

    require(isinstance(record, dict), f"{label} artifact record must be an object")
    require(set(record) == {"path", "sha256", "size", "mode"}, f"{label} artifact fields changed")
    relative = _safe_relative(record["path"], label)
    digest = record["sha256"]
    size = record["size"]
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"{label} artifact digest is invalid")
    require(type(size) is int and size >= 0, f"{label} artifact size is invalid")
    require(type(record["mode"]) is int and 0 <= record["mode"] <= 0o777, f"{label} artifact mode is invalid")
    root = root.resolve(strict=True)
    path = root / relative
    require(path.resolve(strict=False).is_relative_to(root), f"unsafe {label} artifact path")
    require_regular(path, label)
    observed = artifact_record(root, path)
    require(observed == record, f"{label} artifact identity changed")
    return path


def _copy_regular(source: Path, destination: Path, label: str) -> None:
    require_regular(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists() and not destination.is_symlink(), f"retained {label} already exists")
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))
    require(sha256(source) == sha256(destination)
            and stat.S_IMODE(source.stat().st_mode) == stat.S_IMODE(destination.stat().st_mode),
            f"retained {label} copy changed identity")


def _copy_tree(source: Path, destination: Path, label: str) -> None:
    """Copy one finite regular-file tree without relaxing its physical shape."""

    require(source.is_dir() and not source.is_symlink(), f"unsafe {label} root")
    require(not destination.exists() and not destination.is_symlink(),
            f"retained {label} root already exists")
    destination.mkdir(parents=True)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        target = destination / relative
        mode = item.lstat().st_mode
        require(not stat.S_ISLNK(mode), f"unsafe {label} symlink: {relative}")
        if stat.S_ISDIR(mode):
            target.mkdir()
            os.chmod(target, stat.S_IMODE(mode))
        else:
            require(stat.S_ISREG(mode), f"unsafe {label} node: {relative}")
            _copy_regular(item, target, f"{label} {relative}")


def _preparation_retained_paths(work: Path) -> set[str]:
    """Return the full copied preparation cohort, rejecting an open file shape."""

    root = work / PREPARATION_RETAINED_ROOT
    require(root.is_dir() and not root.is_symlink(), "retained static preparation root is unsafe")
    paths: set[str] = set()
    for item in root.rglob("*"):
        mode = item.lstat().st_mode
        relative = item.relative_to(work).as_posix()
        require(not stat.S_ISLNK(mode), f"retained static preparation has symlink: {relative}")
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), f"retained static preparation has non-regular node: {relative}")
        paths.add(relative)
    require(paths, "retained static preparation is empty")
    return paths


def _copy_static_preparation_cohort(work: Path, inputs: Mapping[str, Mapping[str, object]]) -> None:
    """Retain the complete selected preparation, not only its summary receipt."""

    preparation = Path(str(inputs["static_preparation"]["path"]))
    require(preparation.name == "preparation.json", "static preparation filename changed")
    _require_external_identity(preparation, inputs["static_preparation"], "static preparation")
    _copy_tree(preparation.parent, work / PREPARATION_RETAINED_ROOT, "static preparation")
    retained = work / PREPARATION_RETAINED_ROOT / "preparation.json"
    require(retained.read_bytes() == preparation.read_bytes()
            and stat.S_IMODE(retained.stat().st_mode) == stat.S_IMODE(preparation.stat().st_mode),
            "retained static preparation record changed")


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "-c", f"safe.directory={root}", *arguments], cwd=root
        )
    except subprocess.CalledProcessError as error:
        raise ReceiptError(f"git source identity query failed: {' '.join(arguments)}") from error


def checkout_source_digest(root: Path) -> str:
    """Match the source/product digest used by the selected native products."""

    names = sorted(
        set(_git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0"))
        - {b""}
    )
    result = hashlib.sha256()
    for name in names:
        path = root / os.fsdecode(name)
        try:
            mode = path.lstat().st_mode
            data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        except OSError as error:
            raise ReceiptError(f"source digest cannot read {path}") from error
        result.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        result.update(hashlib.sha256(data).digest())
    return result.hexdigest()


def source_identity(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    require(
        not _git(root, "status", "--porcelain", "--untracked-files=all").strip(),
        "receipt collection requires a clean source checkout",
    )
    return {
        "revision": _git(root, "rev-parse", "HEAD").decode("ascii").strip(),
        "tree": _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip(),
        "source_sha256": checkout_source_digest(root),
    }


def capture_source(root: Path, output: Path) -> None:
    require(not output.exists() and not output.is_symlink(), "source snapshot output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {"schema": SOURCE_SNAPSHOT_SCHEMA, "identity": source_identity(root)},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _validate_source_identity(value: object, label: str) -> dict[str, object]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == {"revision", "tree", "source_sha256"},
            f"{label} fields changed")
    for key in ("revision", "tree"):
        require(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{40}", value[key]) is not None,
                f"{label} {key} is invalid")
    for key in ("source_sha256",):
        require(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None,
                f"{label} {key} is invalid")
    return dict(value)


def _load_source_snapshot(path: Path) -> dict[str, object]:
    value = load_json_object(path, "source snapshot")
    require(set(value) == {"schema", "identity"} and value["schema"] == SOURCE_SNAPSHOT_SCHEMA,
            "source snapshot schema changed")
    return _validate_source_identity(value["identity"], "source snapshot identity")


def _record_external(path: Path, label: str) -> dict[str, object]:
    require_regular(path, label)
    return {"sha256": sha256(path), "size": path.stat().st_size, "mode": stat.S_IMODE(path.stat().st_mode)}


def _validate_input_record(value: object, label: str) -> dict[str, object]:
    require(isinstance(value, dict), f"{label} input record must be an object")
    require(set(value) == {"path", "sha256", "size", "mode"}, f"{label} input fields changed")
    path = value["path"]
    require(isinstance(path, str) and path.startswith("/") and "\x00" not in path,
            f"{label} input path is invalid")
    digest = value["sha256"]
    size = value["size"]
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"{label} input digest is invalid")
    require(type(size) is int and size >= 0, f"{label} input size is invalid")
    require(type(value["mode"]) is int and 0 <= value["mode"] <= 0o777, f"{label} input mode is invalid")
    return dict(value)


def _load_inputs(path: Path) -> dict[str, dict[str, object]]:
    value = load_json_object(path, "input identities")
    require(set(value) == {"format", "inputs"} and value["format"] == INPUT_SCHEMA,
            "input identity schema changed")
    inputs = value["inputs"]
    require(isinstance(inputs, dict) and tuple(sorted(inputs)) == tuple(sorted(INPUT_NAMES)),
            "input identity roster changed")
    return {name: _validate_input_record(inputs[name], name) for name in INPUT_NAMES}


def _load_historical_inputs(path: Path) -> dict[str, dict[str, object]]:
    value = load_json_object(path, "historical input identities")
    require(set(value) == {"format", "inputs"}
            and value["format"] == "owned-pthread-alias-contract-inputs-v1",
            "historical input identity schema changed")
    inputs = value["inputs"]
    require(isinstance(inputs, dict) and tuple(sorted(inputs)) == tuple(sorted(HISTORICAL_INPUT_NAMES)),
            "historical input roster changed")
    result: dict[str, dict[str, object]] = {}
    for name in HISTORICAL_INPUT_NAMES:
        item = inputs[name]
        require(isinstance(item, dict) and set(item) == {"path", "sha256"},
                f"historical {name} fields changed")
        require(isinstance(item["path"], str) and item["path"].startswith("/"),
                f"historical {name} path is invalid")
        require(isinstance(item["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                f"historical {name} digest is invalid")
        result[name] = dict(item)
    return result


def _input_copy_path(name: str) -> str:
    paths = {
        "probe": "retained/collector/probe.c",
        "reader": "retained/collector/reader.py",
        "runner": "retained/collector/runner.sh",
        "oracle_compiler": "retained/oracle/compiler-wrapper",
        "musl_shared": "retained/oracle/libc.so",
        "musl_archive": "retained/oracle/libc.a",
        "static_driver": "retained/products/static-driver",
        "static_libc": "retained/products/static-libc.a",
        "static_crt1": "retained/products/static-crt1.o",
        "static_rcrt1": "retained/products/static-rcrt1.o",
        "static_crti": "retained/products/static-crti.o",
        "static_crtn": "retained/products/static-crtn.o",
        "static_builtins": "retained/products/static-builtins.a",
        "dynamic_driver": "retained/products/dynamic-driver",
        "dynamic_crt1": "retained/products/dynamic-crt1.o",
        "dynamic_scrt1": "retained/products/dynamic-Scrt1.o",
        "dynamic_crti": "retained/products/dynamic-crti.o",
        "dynamic_crtn": "retained/products/dynamic-crtn.o",
        "dynamic_attach": "retained/products/dynamic-attach.o",
        "dynamic_builtins": "retained/products/dynamic-builtins.a",
        "dynamic_libc": "retained/products/dynamic-libc.so",
        "dynamic_loader": "retained/products/dynamic-loader",
        "product_report": "retained/products/anchor-report.json",
        "static_preparation": "retained/products/static-preparation.json",
    }
    return paths[name]


def _require_external_identity(path: Path, expected: Mapping[str, object], label: str) -> None:
    observed = _record_external(path, label)
    require(observed == {"sha256": expected["sha256"], "size": expected["size"], "mode": expected["mode"]},
            f"{label} changed after input capture")


def _image_record(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    require_regular(resolved, "resolved pinned image input")
    return {
        "path": str(resolved),
        "sha256": sha256(resolved),
        "size": resolved.stat().st_size,
        "mode": stat.S_IMODE(resolved.stat().st_mode),
    }


def live_image_manifest() -> dict[str, object]:
    """Regenerate the finite tool closure from the pinned evidence image."""

    commands = [shutil.which(name, path=IMAGE_PATH) for name in IMAGE_COMMANDS]
    require(all(commands), "pinned image lacks a pthread receipt command")
    paths = [Path(str(path)) for path in commands]
    paths.extend(Path(path) for path in IMAGE_FIXED_PATHS)
    try:
        for name in ("cc1", "collect2", "liblto_plugin.so"):
            paths.append(Path(subprocess.check_output(
                ["/usr/bin/gcc", "-print-prog-name=" + name], text=True
            ).strip()))
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError("pinned image GCC support identity is unavailable") from error
    require(all(path.is_absolute() for path in paths), "pinned image tool placement differs")
    return {
        "schema": "crabc.x86_64-owned-pthread-timed-feature-image-inputs/v1",
        "image": PINNED_IMAGE,
        "path": IMAGE_PATH,
        "files": {str(path): _image_record(path) for path in sorted(set(paths))},
    }


def trusted_image_manifest() -> dict[str, object]:
    """Read the validator-owned image manifest; report JSON cannot replace it."""

    value = load_json_object(IMAGE_MANIFEST_PATH, "trusted pthread image manifest")
    require(set(value) == {"schema", "image", "path", "files"}
            and value["schema"] == "crabc.x86_64-owned-pthread-timed-feature-image-inputs/v1"
            and value["image"] == PINNED_IMAGE and value["path"] == IMAGE_PATH,
            "trusted pthread image manifest differs")
    files = value["files"]
    require(isinstance(files, dict) and files, "trusted pthread image manifest has no files")
    for invocation, record in files.items():
        require(isinstance(invocation, str) and invocation.startswith("/")
                and isinstance(record, dict) and set(record) == {"path", "sha256", "size", "mode"}
                and isinstance(record["path"], str) and record["path"].startswith("/")
                and isinstance(record["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None
                and type(record["size"]) is int and record["size"] >= 0
                and type(record["mode"]) is int and 0 <= record["mode"] <= 0o777,
                "trusted pthread image input identity differs")
    return value


def _image_copy_path(invocation: str) -> str:
    return "retained/image/" + hashlib.sha256(invocation.encode("utf-8")).hexdigest()


def _copy_image_inputs(work: Path, manifest: Mapping[str, object]) -> None:
    files = manifest["files"]
    require(isinstance(files, dict), "trusted pthread image manifest files differ")
    for invocation, record in files.items():
        require(isinstance(invocation, str) and isinstance(record, dict), "trusted image input differs")
        path = Path(str(record["path"]))
        observed = _image_record(path)
        require(observed == record, f"pinned image input changed before collection: {invocation}")
        _copy_regular(path, work / _image_copy_path(invocation), f"pinned image input {invocation}")


def _validate_image_inputs(
    work: Path, value: object, artifacts: Mapping[str, object], collector_git_files: Mapping[str, tuple[int, bytes, bool]],
) -> dict[str, object]:
    """Replay every copied image input against validator source, path, bytes, and mode."""

    require(IMAGE_MANIFEST_SOURCE in collector_git_files
            and collector_git_files[IMAGE_MANIFEST_SOURCE][1] == IMAGE_MANIFEST_PATH.read_bytes(),
            "retained image manifest does not match validator image authority")
    manifest = trusted_image_manifest()
    require(isinstance(value, dict) and set(value) == set(manifest["files"]),
            "receipt image input roster differs")
    for invocation, expected in manifest["files"].items():
        binding = value[invocation]
        require(isinstance(binding, dict) and set(binding) == {"path", "sha256", "size", "mode", "retained"}
                and {key: binding[key] for key in ("path", "sha256", "size", "mode")} == expected
                and binding["retained"] == _image_copy_path(invocation),
                f"receipt image input identity differs: {invocation}")
        retained = validate_retained_artifact(work, artifacts[str(binding["retained"])], f"image input {invocation}")
        require({key: artifacts[str(binding["retained"])][key] for key in ("sha256", "size", "mode")} ==
                {key: expected[key] for key in ("sha256", "size", "mode")},
                f"retained image input differs: {invocation}")
        require(retained == work / str(binding["retained"]), "retained image input path escaped receipt")
    return manifest


def require_archive_relocation_stream(path: Path, artifact: Path, logical_path: str) -> None:
    """Derive the full archive ``readelf --relocs`` rendering from retained members.

    The approved authority exposes the per-ELF relocation parser.  This finite
    receipt also records the two selected archives, whose raw stream prefixes
    each member with ``File:``.  Keep that archive framing here rather than
    treating report-owned text as an observation.
    """

    try:
        members = [(f"{logical_path}({name})", elf_bytes(body))
                   for name, body in archive_members(artifact.read_bytes())]
    except (OSError, ValueError) as error:
        raise ReceiptError("retained archive relocation input differs") from error
    expected: list[tuple[str, str]] = []
    rows: list[tuple[str, int, int, str, int, str, int]] = []
    for member, elf in members:
        for section in elf.sections:
            if section[1] != 4:
                continue
            require(section[9] == 24 and section[5] % 24 == 0,
                    "retained archive relocation table differs")
            expected.append((member, "Relocation section '%s' at offset 0x%x contains %d %s:" % (
                section_name(elf, section), section[4], section[5] // 24,
                "entry" if section[5] == 24 else "entries",
            )))
            for offset in range(0, section[5], 24):
                destination, info, addend = elf.unpack("<QQq", section[4] + offset)
                symbol = elf.symbol_row(section[6], info >> 32)
                kind = info & 0xffffffff
                require(kind in RAW_ARCHIVE_RELOCATION_NAMES, "unclassified archive ELF relocation")
                name = symbol["name"]
                if symbol["type"] == "3" and not name:
                    name = section_name(elf, elf.sections[symbol["section"]])
                rows.append((member, destination, info, RAW_ARCHIVE_RELOCATION_NAMES[kind],
                             symbol["value"], name, addend))
    actual_headers: list[tuple[str, str]] = []
    actual_rows: list[tuple[str, int, int, str, int, str, int]] = []
    member = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("File: "):
            member = line[6:]
        elif line.startswith("Relocation section "):
            actual_headers.append((member, line))
        else:
            match = re.fullmatch(r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(R_X86_64_\w+)\s*(.*)", line)
            if match:
                destination, info, kind, tail = match.groups()
                fields = tail.split()
                if len(fields) == 1:
                    value, name, addend = 0, "", int(fields[0], 16)
                else:
                    require(len(fields) == 4 and fields[2] in ("+", "-"),
                            "malformed archive raw relocation target")
                    value, name = int(fields[0], 16), fields[1].split("@", 1)[0]
                    addend = int(fields[3], 16) * (1 if fields[2] == "+" else -1)
                actual_rows.append((member, int(destination, 16), int(info, 16), kind, value, name, addend))
            else:
                require(not line.strip() or line.lstrip().startswith("Offset")
                        or line == "There are no relocations in this file.",
                        "unexpected archive raw relocation text")
    require(actual_headers == expected, "raw archive relocation table header differs from ELF")
    require(actual_rows == rows, f"raw archive relocations do not describe retained ELF: {path.name}")


def _manifest_files(value: object, label: str) -> dict[str, str]:
    require(isinstance(value, dict), f"{label} file roster must be an object")
    result: dict[str, str] = {}
    for name, digest in value.items():
        relative = _safe_relative(name, f"{label} file")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                f"{label} digest is invalid: {relative}")
        result[relative.as_posix()] = digest
    return result


def _anchor_artifact(anchor: Mapping[str, object], name: str, label: str) -> Mapping[str, object]:
    artifacts = anchor.get("artifacts")
    require(isinstance(artifacts, dict) and name in artifacts, f"anchor missing {label}")
    item = artifacts[name]
    require(isinstance(item, dict) and set(item) == {"path", "sha256", "size"},
            f"anchor {label} artifact fields changed")
    _safe_relative(item["path"], f"anchor {label}")
    require(isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
            f"anchor {label} digest is invalid")
    require(type(item["size"]) is int and item["size"] >= 0, f"anchor {label} size is invalid")
    return item


def _same_external_record(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    return left.get("sha256") == right.get("sha256") and left.get("size") == right.get("size")


def _validate_dynamic_materialization_state(
    state: object,
    source_sha256: object,
    dynamic_files: Mapping[str, str],
    label: str,
) -> None:
    """Bind the selected dynamic materialization boundary without promoting it."""

    require(isinstance(state, dict) and set(state) == DYNAMIC_STATE_FIELDS,
            f"{label} fields changed")
    require(state["schema"] == "crabc.x86_64-owned-dynamic-materialization/v1"
            and state["status"] == "materialized-unqualified",
            f"{label} schema or status changed")
    require(state["source_sha256"] == source_sha256,
            f"{label} source changed")
    contracts = state["contracts"]
    require(isinstance(contracts, dict) and set(contracts) == DYNAMIC_STATE_CONTRACTS
            and all(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                    for digest in contracts.values()),
            f"{label} contract roster changed")
    payload_files = state["payload_files"]
    expected_payloads = {
        name: digest for name, digest in dynamic_files.items() if name != DYNAMIC_STATE_PATH
    }
    require(payload_files == expected_payloads,
            f"{label} payload binding changed")
    require(state["runtime_v1_published"] is False
            and state["campaign_complete"] is False
            and state["public_support"] is False,
            f"{label} crossed its qualification boundary")
    require(state["modes"] == DYNAMIC_STATE_MODES
            and state["runtime_profile"] == DYNAMIC_STATE_PROFILE
            and state["qualification"] == DYNAMIC_STATE_QUALIFICATION,
            f"{label} runtime boundary changed")


def _validate_link_input_modes(inputs: Mapping[str, Mapping[str, object]]) -> None:
    """Bind retained role modes to the collector Git-owned product policy."""

    static_inputs = {
        "usr/lib/crt1.o": "static_crt1",
        "usr/lib/rcrt1.o": "static_rcrt1",
        "usr/lib/crti.o": "static_crti",
        "usr/lib/crtn.o": "static_crtn",
        "usr/lib/libc.a": "static_libc",
        "usr/lib/libcrabc-builtins.a": "static_builtins",
    }
    dynamic_inputs = {
        "usr/lib/crt1.o": "dynamic_crt1",
        "usr/lib/Scrt1.o": "dynamic_scrt1",
        "usr/lib/crti.o": "dynamic_crti",
        "usr/lib/crtn.o": "dynamic_crtn",
        "usr/lib/crabc-dynamic-attach.o": "dynamic_attach",
        "usr/lib/libcrabc-builtins.a": "dynamic_builtins",
        "usr/lib/libc.so": "dynamic_libc",
    }
    for contract, captured, label in (
        (product_evidence.STATIC_LINK_INPUT_MODES, static_inputs, "static"),
        (product_evidence.DYNAMIC_LINK_INPUT_MODES, dynamic_inputs, "dynamic"),
    ):
        require(set(contract) == set(captured), f"{label} product mode contract changed")
        for relative, expected_mode in contract.items():
            value = inputs[captured[relative]]
            require(value["mode"] == expected_mode,
                    f"{label} selected product link input mode differs: {relative}")


def _validate_current_product_links(
    work: Path, inputs: Mapping[str, Mapping[str, object]],
) -> None:
    """Run the existing physical product validators before retention."""

    static_root = Path(str(inputs["static_driver"]["path"])).parent.parent
    dynamic_root = Path(str(inputs["dynamic_driver"]["path"])).parent.parent
    rows = (
        (static_root, "static-contract", "static"),
        (static_root, "static-pie-contract", "static-pie"),
        (dynamic_root, "dynamic-pie-contract", "pie"),
        (dynamic_root, "dynamic-non-pie-contract", "non-pie"),
    )
    try:
        for product, binary, linkage in rows:
            suffix = ".link.json" if linkage.startswith("static") else ".crabc-link.json"
            product_evidence.validate_link(
                product, work / "contract.o", work / binary, work / f"{binary}{suffix}", linkage,
                export_dynamic=linkage in {"pie", "non-pie"},
            )
    except product_evidence.ProductEvidenceError as error:
        raise ReceiptError(f"selected product physical link validation failed: {error}") from error


def _validate_product_anchor(
    anchor_path: Path,
    inputs: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """Authenticate exactly the b41 supplied product materialization.

    The loader-debug report is an upstream component receipt.  It is not
    reclassified as pthread evidence; this component uses only its retained
    product/source identities and then records its own alias observations.
    """

    anchor = load_json_object(anchor_path, "selected product anchor")
    required = {
        "schema", "status", "source_commit", "source_sha256", "public_support",
        "family_complete", "artifacts",
    }
    require(required <= set(anchor), "selected product anchor fields are incomplete")
    require(anchor["schema"] == "crabc.x86_64-loader-debug-crt-abi/v1"
            and anchor["status"] == "component-verified"
            and anchor["public_support"] is False and anchor["family_complete"] is False,
            "selected product anchor is not a non-promoting component receipt")
    require(isinstance(anchor["source_commit"], str)
            and re.fullmatch(r"[0-9a-f]{40}", anchor["source_commit"]) is not None
            and isinstance(anchor["source_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", anchor["source_sha256"]) is not None,
            "selected product anchor source identity is invalid")

    static_driver = Path(str(inputs["static_driver"]["path"]))
    static_libc = Path(str(inputs["static_libc"]["path"]))
    dynamic_driver = Path(str(inputs["dynamic_driver"]["path"]))
    dynamic_libc = Path(str(inputs["dynamic_libc"]["path"]))
    dynamic_loader = Path(str(inputs["dynamic_loader"]["path"]))
    static_root = static_driver.parent.parent
    dynamic_root = dynamic_driver.parent.parent
    require(static_libc == static_root / "usr/lib/libc.a", "static input root is inconsistent")
    require(dynamic_libc == dynamic_root / "usr/lib/libc.so", "dynamic input root is inconsistent")
    require(dynamic_loader == dynamic_root / "lib/ld-crabc-x86_64.so.1", "dynamic loader input root is inconsistent")
    static_manifest_path = static_root / "share/crabc/manifest.json"
    dynamic_manifest_path = dynamic_root / "share/crabc/manifest.json"
    dynamic_state_path = dynamic_root / "share/crabc/dynamic-product-state.json"
    for path, label in (
        (static_manifest_path, "static manifest"),
        (dynamic_manifest_path, "dynamic manifest"),
        (dynamic_state_path, "dynamic product state"),
    ):
        require_regular(path, label)

    static_manifest = load_json_object(static_manifest_path, "static manifest")
    require(static_manifest.get("schema") == 1
            and static_manifest.get("format") == "crabc-x86-64-owned-static-sysroot-v1",
            "selected static manifest schema changed")
    installed = static_manifest.get("installed")
    require(isinstance(installed, dict), "selected static manifest has no installed roster")
    static_files = _manifest_files(installed.get("files"), "selected static manifest")
    dynamic_manifest = load_json_object(dynamic_manifest_path, "dynamic manifest")
    require(dynamic_manifest.get("schema") == 1
            and dynamic_manifest.get("format") == "crabc-x86-64-owned-dynamic-sysroot-v1",
            "selected dynamic manifest schema changed")
    dynamic_files = _manifest_files(dynamic_manifest.get("files"), "selected dynamic manifest")
    dynamic_state = load_json_object(dynamic_state_path, "dynamic product state")
    _validate_dynamic_materialization_state(
        dynamic_state, anchor["source_sha256"], dynamic_files, "selected dynamic product state"
    )

    for relative, input_name, files, root, label in (
        ("bin/crabc-cc", "static_driver", static_files, static_root, "static driver"),
        ("usr/lib/libc.a", "static_libc", static_files, static_root, "static libc"),
        ("bin/crabc-cc-dynamic", "dynamic_driver", dynamic_files, dynamic_root, "dynamic driver"),
        ("usr/lib/crt1.o", "dynamic_crt1", dynamic_files, dynamic_root, "dynamic CRT entry"),
        ("usr/lib/Scrt1.o", "dynamic_scrt1", dynamic_files, dynamic_root, "dynamic PIE CRT entry"),
        ("usr/lib/crti.o", "dynamic_crti", dynamic_files, dynamic_root, "dynamic CRT prologue"),
        ("usr/lib/crtn.o", "dynamic_crtn", dynamic_files, dynamic_root, "dynamic CRT epilogue"),
        ("usr/lib/crabc-dynamic-attach.o", "dynamic_attach", dynamic_files, dynamic_root, "dynamic CRT attach"),
        ("usr/lib/libcrabc-builtins.a", "dynamic_builtins", dynamic_files, dynamic_root, "dynamic builtins"),
        ("usr/lib/libc.so", "dynamic_libc", dynamic_files, dynamic_root, "dynamic libc"),
        ("lib/ld-crabc-x86_64.so.1", "dynamic_loader", dynamic_files, dynamic_root, "dynamic loader"),
    ):
        require(relative in files and files[relative] == inputs[input_name]["sha256"],
                f"selected {label} is not sealed by its manifest")
        _require_external_identity(root / relative, inputs[input_name], label)

    for anchor_name, path, label in (
        ("static-manifest", static_manifest_path, "static manifest"),
        ("dynamic-manifest", dynamic_manifest_path, "dynamic manifest"),
        ("candidate-libc", dynamic_libc, "dynamic libc"),
        ("candidate-loader", dynamic_loader, "dynamic loader"),
    ):
        require(_same_external_record(_anchor_artifact(anchor, anchor_name, label), _record_external(path, label)),
                f"selected product anchor does not bind {label}")

    # The complete preparation is retained and replayed after Git source
    # authority is captured. Do not accept a summary-field substitute here.

    oracle = anchor.get("oracle")
    require(isinstance(oracle, dict)
            and oracle.get("version") == MUSL_RELEASE
            and oracle.get("runtime_sha256") == inputs["musl_shared"]["sha256"]
            and oracle.get("compiler_wrapper_sha256") == inputs["oracle_compiler"]["sha256"],
            "selected product anchor oracle boundary changed")

    return {
        "anchor": anchor,
        "static_manifest_path": static_manifest_path,
        "dynamic_manifest_path": dynamic_manifest_path,
        "dynamic_state_path": dynamic_state_path,
        "static_files": static_files,
        "dynamic_files": dynamic_files,
    }


def _symbol_rows(path: Path, wanted_tables: set[str]) -> list[SymbolRow]:
    result: list[SymbolRow] = []
    member = ""
    table = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("File: "):
            member = line[6:]
            table = ""
            continue
        if line.startswith("Symbol table '"):
            parts = line.split("'", 2)
            require(len(parts) >= 2, f"malformed symbol table heading in {path}")
            table = parts[1]
            continue
        fields = line.split()
        if table in wanted_tables and len(fields) >= 8 and fields[0].endswith(":"):
            result.append(SymbolRow(
                member, fields[1], fields[3], fields[4], fields[5], fields[6],
                fields[7].split("@", 1)[0],
            ))
    return result


def _defined_by_name(path: Path, wanted_tables: set[str]) -> dict[str, list[SymbolRow]]:
    result: dict[str, list[SymbolRow]] = defaultdict(list)
    for row in _symbol_rows(path, wanted_tables):
        if _is_real_defining_section(row.section):
            result[row.name].append(row)
    return result


def _is_real_defining_section(section: str) -> bool:
    """Accept only a positive ELF section index as a retained definition.

    ``readelf`` prints the special ``UND``, ``ABS``, and ``COM`` forms in the
    same column as a section index.  None designates a function body in an ELF
    section.  The exact alias proof needs a real, nonzero section identity so
    that equal member/value/type rows cannot turn an absolute or common symbol
    into a fabricated same-definition alias.
    """

    return re.fullmatch(r"[1-9][0-9]*", section) is not None


def _one(table: Mapping[str, list[SymbolRow]], name: str, path: Path) -> SymbolRow:
    rows = table.get(name, [])
    require(len(rows) == 1, f"{path}: expected one defined {name}, found {rows}")
    return rows[0]


def _shape(row: SymbolRow) -> tuple[str, str, str]:
    return row.symbol_type, row.binding, row.visibility


def _row_data(row: SymbolRow) -> dict[str, str]:
    return {
        "member": row.member,
        "value": row.value,
        "type": row.symbol_type,
        "binding": row.binding,
        "visibility": row.visibility,
        "section": row.section,
        "name": row.name,
    }


def _require_same_definition(alias: SymbolRow, target: SymbolRow, path: Path) -> None:
    require(
        same_definition(alias, target),
        f"{path}: {alias.name} and {target.name} do not share one defining member/value/type/section",
    )


def _dynamic_symbols(path: Path) -> dict[str, list[SymbolRow]]:
    table = _defined_by_name(path, {".dynsym"})
    for name, _ in ALIASES:
        row = _one(table, name, path)
        require(_shape(row) == ("FUNC", "WEAK", "DEFAULT"),
                f"{path}: {name} is not FUNC WEAK DEFAULT")
    for provider in {provider for _, provider in ALIASES}:
        require(not table.get(provider), f"{path}: internal provider leaked into dynamic symbols")
    return table


def _shared_symbols(path: Path) -> tuple[dict[str, list[SymbolRow]], dict[str, dict[str, object]]]:
    table = _defined_by_name(path, {".symtab"})
    definitions: dict[str, dict[str, object]] = {}
    for name, provider in ALIASES:
        alias = _one(table, name, path)
        target = _one(table, provider, path)
        require(_shape(alias) == ("FUNC", "WEAK", "DEFAULT"),
                f"{path}: {name} is not FUNC WEAK DEFAULT")
        require(target.symbol_type == "FUNC" and target.binding == "LOCAL",
                f"{path}: {provider} is not a local shared FUNC body")
        _require_same_definition(alias, target, path)
        definitions[name] = {"alias": _row_data(alias), "provider": _row_data(target)}
    return table, definitions


def _static_symbols(
    path: Path, provider_shapes: Mapping[str, tuple[str, str, str]] = CANDIDATE_STATIC_PROVIDER_SHAPES,
) -> tuple[dict[str, list[SymbolRow]], dict[str, dict[str, object]]]:
    table = _defined_by_name(path, {".symtab"})
    definitions: dict[str, dict[str, object]] = {}
    for name, provider in ALIASES:
        alias = _one(table, name, path)
        target = _one(table, provider, path)
        require(_shape(alias) == ("FUNC", "WEAK", "DEFAULT"),
                f"{path}: {name} is not FUNC WEAK DEFAULT")
        expected = provider_shapes[provider]
        require(_shape(target) == expected,
                f"{path}: {provider} archive binding differs from musl source form")
        _require_same_definition(alias, target, path)
        definitions[name] = {"alias": _row_data(alias), "provider": _row_data(target)}
    return table, definitions



def evaluate_alias_contract(work: Path) -> dict[str, object]:
    """Recompute the finite ELF alias and public-source-caller observations."""

    musl_dynamic = _dynamic_symbols(work / "musl-dynamic-symbols.txt")
    candidate_dynamic = _dynamic_symbols(work / "candidate-dynamic-symbols.txt")
    musl_shared, musl_shared_defs = _shared_symbols(work / "musl-shared-symbols.txt")
    candidate_shared, candidate_shared_defs = _shared_symbols(work / "candidate-shared-symbols.txt")
    musl_static, musl_static_defs = _static_symbols(
        work / "musl-static-symbols.txt", MUSL_STATIC_PROVIDER_SHAPES
    )
    candidate_static, candidate_static_defs = _static_symbols(
        work / "candidate-static-symbols.txt", CANDIDATE_STATIC_PROVIDER_SHAPES
    )

    shapes: dict[str, dict[str, list[str]]] = {}
    for placement, left, right in (
        ("dynamic", musl_dynamic, candidate_dynamic),
        ("shared", musl_shared, candidate_shared),
        ("static", musl_static, candidate_static),
    ):
        values: dict[str, list[str]] = {}
        for name, _ in ALIASES:
            left_shape = _shape(_one(left, name, work / f"musl {placement} symbols"))
            right_shape = _shape(_one(right, name, work / f"candidate {placement} symbols"))
            require(left_shape == right_shape, f"{placement} binding/visibility mismatch for {name}")
            values[name] = list(right_shape)
        shapes[placement] = values

    return {
        "aliases": [{"public": public, "provider": provider} for public, provider in ALIASES],
        "archive_hidden_providers": list(ARCHIVE_HIDDEN),
        "archive_local_providers": list(ARCHIVE_LOCAL),
        "alias_shapes": shapes,
        "same_definition": {
            "shared": candidate_shared_defs,
            "static": candidate_static_defs,
            "musl_shared": musl_shared_defs,
            "musl_static": musl_static_defs,
        },
    }



def evaluate_final_extraction(work: Path) -> dict[str, object]:
    """Require the four aliases in actual final links, not merely map text."""

    def static(label: str) -> dict[str, dict[str, object]]:
        path = work / f"{label}.symbols.txt"
        table, definitions = _static_symbols(path, FINAL_STATIC_PROVIDER_SHAPES)
        result: dict[str, dict[str, object]] = {}
        for public, provider in ALIASES:
            alias = _one(table, public, path)
            body = _one(table, provider, path)
            _require_same_definition(alias, body, path)
            result[public] = {"alias": _row_data(alias), "provider": _row_data(body),
                              "same_definition": definitions[public]}
        return result

    def dynamic(label: str) -> dict[str, dict[str, object]]:
        path = work / f"{label}.symbols.txt"
        rows = _symbol_rows(path, {".dynsym"})
        result: dict[str, dict[str, object]] = {}
        for public, provider in ALIASES:
            public_rows = [row for row in rows if row.name == public]
            provider_rows = [row for row in rows if row.name == provider]
            require(len(public_rows) == 1 and public_rows[0].section == "UND"
                    and _shape(public_rows[0]) == ("FUNC", "GLOBAL", "DEFAULT"),
                    f"{path}: final dynamic public import differs: {public}")
            require(not provider_rows, f"{path}: final dynamic private provider leaked: {provider}")
            result[public] = _row_data(public_rows[0])
        return result

    return {
        "static": static("static-contract"),
        "static_pie": static("static-pie-contract"),
        "dynamic_pie": dynamic("dynamic-pie-contract"),
        "dynamic_non_pie": dynamic("dynamic-non-pie-contract"),
    }


def evaluate_feature_source(root: Path) -> dict[str, object]:
    """Authenticate only source feature configuration and its exact four aliases."""

    with (root / "compat/x86_64/parity.toml").open("rb") as stream:
        ledger = tomllib.load(stream)
    rows = [row for row in ledger["feature_archive"] if row["id"] == FEATURE]
    require(len(rows) == 1 and rows[0].get("state") == "planned"
            and rows[0].get("evidence_record") is None, "timed feature ledger differs")
    aliases = {(row["name"], row["target"], row["binding"]) for row in rows[0]["aliases"]}
    require({(public, provider, "weak-same-address") for public, provider in ALIASES} <= aliases,
            "timed feature alias ledger differs")
    cargo = (root / "libc/Cargo.toml").read_text(encoding="utf-8")
    require(re.search(r"^x86-owned-static-runtime\s*=\s*\[", cargo, re.MULTILINE) is not None,
            "timed feature Cargo route differs")
    builder = (root / "scripts/build_x86_64_owned_sysroot.py").read_text(encoding="utf-8")
    require('"--features",\n        "x86-owned-static-runtime",' in builder,
            "timed feature builder argv source differs")
    module_root = (root / "libc/src/c_abi/x86_64/static_c_abi.rs").read_text(encoding="utf-8")
    for leaf in ("pthread_create_join.rs", "pthread_mutex.rs", "pthread_cond.rs"):
        require(f'#[path = "{leaf}"]' in module_root,
                f"timed feature static C ABI leaf route differs: {leaf}")
    condition_route = (root / "libc/src/c_abi/x86_64/pthread_cond.rs").read_text(encoding="utf-8")
    require('#[cfg(feature = "x86-owned-static-runtime")]\n#[path = "owned_pthread_cond.rs"]' in condition_route,
            "timed feature owned condition route differs")
    source_paths = {
        "pthread_cond_timedwait": "libc/src/c_abi/x86_64/owned_pthread_cond.rs",
        "pthread_mutex_timedlock": "libc/src/c_abi/x86_64/pthread_mutex.rs",
        "pthread_timedjoin_np": "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "pthread_tryjoin_np": "libc/src/c_abi/x86_64/pthread_create_join.rs",
    }
    for public, provider in ALIASES:
        source = (root / source_paths[public]).read_text(encoding="utf-8")
        require(f".hidden {provider}" in source and f".weak {public}" in source
                and f".set {public}, {provider}" in source,
                f"timed feature source alias differs: {public}")
    return {
        "feature": FEATURE,
        "aliases": [{"public": public, "provider": provider} for public, provider in ALIASES],
        "builder_argv_source": ["--features", FEATURE],
        "product_build_invocation_proven": False,
        "scope": "source feature mapping only; supplied product bytes and final-link rows are separately sealed",
    }

def _header_type(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    matches = re.findall(r"^\s*Type:\s+([A-Z]+)\b", text, flags=re.MULTILINE)
    require(len(matches) == 1, f"{path}: expected one ELF Type header")
    return matches[0]


def evaluate_elf_headers(work: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for binary, expected in ELF_TYPES.items():
        binary_path = work / binary
        require_regular(binary_path, f"ELF {binary}")
        require(binary_path.read_bytes()[:4] == b"\x7fELF", f"{binary}: retained output is not ELF")
        observed = _header_type(work / f"{binary}.file-header.txt")
        require(observed == expected, f"{binary}: expected ELF {expected}, found {observed}")
        elf = Elf(binary_path)
        require(elf.elf_type == {"REL": 1, "EXEC": 2, "DYN": 3}[expected],
                f"{binary}: retained ELF bytes do not match its header observation")
        interpreters = [program for program in elf.programs if program[0] == 3]
        if binary in ("static-contract", "static-pie-contract", "oracle-contract", "contract.o"):
            require(not interpreters, f"{binary}: static/relocatable output has an interpreter")
        elif binary.startswith("musl-dynamic-"):
            require(len(interpreters) == 1
                    and elf.data[interpreters[0][2]:interpreters[0][2] + interpreters[0][5]].rstrip(b"\0")
                    == b"/lib/ld-musl-x86_64.so.1", f"{binary}: musl dynamic interpreter differs")
        else:
            require(len(interpreters) == 1
                    and elf.data[interpreters[0][2]:interpreters[0][2] + interpreters[0][5]].rstrip(b"\0")
                    == INTERPRETER.encode(), f"{binary}: owned dynamic interpreter differs")
        result[binary] = observed
    return result


def _expected_command_argv(name: str, work: str, inputs: Mapping[str, str]) -> list[str]:
    contract = f"{work}/contract.o"
    def link_map(binary: str) -> str:
        return f"-Wl,-Map,{work}/{binary}.map"
    if name == "contract-compile":
        return [
            inputs["dynamic_driver"], "--dynamic-pie", "-std=c11", "-fno-builtin",
            "-fno-stack-protector", "-pthread", "-c", inputs["probe"], "-o", contract,
        ]
    if name == "oracle-link":
        return [
            inputs["oracle_compiler"], "-std=c11", "-static", "-fno-pie", "-no-pie", "-pthread",
            contract, link_map("oracle-contract"), "-o", f"{work}/oracle-contract",
        ]
    if name in {"static-link", "static-pie-link"}:
        mode = "static" if name == "static-link" else "static-pie"
        binary = "static-contract" if mode == "static" else "static-pie-contract"
        require(work.startswith("/workspace/"), "static receipt work path must be mounted at /workspace")
        relative_work = work.removeprefix("/workspace/")
        return [inputs["static_driver"], f"-{mode}", "-pthread", contract,
                "--link-receipt", f"{relative_work}/{binary}.link.json", "-o", f"{work}/{binary}"]
    if name in {"musl-dynamic-pie-link", "musl-dynamic-non-pie-link"}:
        mode = "pie" if name.startswith("musl-dynamic-pie-") else "non-pie"
        binary = f"musl-dynamic-{mode}-contract"
        mode_flag = "-pie" if mode == "pie" else "-no-pie"
        return [
            inputs["oracle_compiler"], "-std=c11", "-pthread", "-rdynamic", mode_flag,
            "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1", contract, link_map(binary),
            "-o", f"{work}/{binary}",
        ]
    if name in {"dynamic-pie-link", "dynamic-non-pie-link"}:
        mode = "pie" if name.startswith("dynamic-pie-") else "non-pie"
        return [
            inputs["dynamic_driver"], f"--dynamic-{mode}", "-pthread", "-rdynamic", contract,
            "-o", f"{work}/dynamic-{mode}-contract",
        ]
    if name == "oracle":
        return [f"{work}/oracle-contract"]
    if name == "static":
        return [f"{work}/static-contract"]
    if name == "static-pie":
        return [f"{work}/static-pie-contract"]
    match = re.fullmatch(r"(musl-dynamic|dynamic)-(pie|non-pie)-(kernel|direct)", name)
    require(match is not None, f"unknown command {name}")
    lane, mode, entry = match.groups()
    root = f"{work}/{lane}-{mode}-root"
    if entry == "kernel":
        return ["chroot", root, "/contract"]
    interpreter = "/lib/ld-musl-x86_64.so.1" if lane == "musl-dynamic" else INTERPRETER
    return ["chroot", root, interpreter, "/contract"]


def validate_command_argv(
    name: str, argv: Sequence[str], work: str, inputs: Mapping[str, str]
) -> None:
    """Require one exact component command, object input, and link-map path."""

    require(name in COMMANDS, f"unknown command {name}")
    require(all(isinstance(value, str) for value in argv), f"{name}: argv must be text")
    expected = _expected_command_argv(name, work, inputs)
    if name in LINK_OUTPUTS and f"{work}/contract.o" not in argv:
        raise ReceiptError(f"{name}: link must consume the one compiled contract object")
    if name in {"static-link", "static-pie-link"}:
        relative_work = work.removeprefix("/workspace/")
        expected_receipt = f"{relative_work}/{LINK_OUTPUTS[name]}.link.json"
        if "--link-receipt" not in argv or expected_receipt not in argv:
            raise ReceiptError(f"{name}: link must retain its exact retained link map")
    elif name in LINK_MAPS and f"-Wl,-Map,{work}/{LINK_MAPS[name]}" not in argv:
        raise ReceiptError(f"{name}: link must retain its exact retained link map")
    require(list(argv) == expected, f"{name}: argv differs from the component contract")


def _argv(path: Path, label: str) -> list[str]:
    value = load_json(path, label)
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label} must be a text argv array")
    return list(value)


def _direct_work_files() -> set[str]:
    files = {
        "execution-environment.json", "input-identities.json", "source-before.json",
        "contract.o", "contract.o.file-header.txt",
    }
    for command in COMMANDS:
        files.update({f"{command}.argv.json", f"{command}.status", f"{command}.stdout", f"{command}.stderr"})
    for binary in ELF_TYPES:
        if binary != "contract.o":
            files.add(binary)
            files.add(f"{binary}.file-header.txt")
    files.update(LINK_MAPS.values())
    files.update(SYMBOL_STREAMS)
    files.update(DYNAMIC_LINK_RECEIPTS)
    files.update(STATIC_LINK_RECEIPTS)
    files.update(STATIC_LINK_TRACES)
    return files


def _tree_record(root: Path) -> dict[str, object]:
    require(root.is_dir() and not root.is_symlink(), f"unsafe runtime root: {root}")
    directories: list[str] = []
    files: dict[str, dict[str, object]] = {}
    symlinks: dict[str, str] = {}
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(dirnames):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                symlinks[relative] = os.readlink(path)
            else:
                require(path.is_dir(), f"non-directory runtime entry: {path}")
                directories.append(relative)
        for name in sorted(filenames):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                symlinks[relative] = os.readlink(path)
            else:
                require_regular(path, "runtime root file")
                files[relative] = {"sha256": sha256(path), "size": path.stat().st_size}
    return {"directories": sorted(directories), "files": files, "symlinks": symlinks}


def _write_tree_record(root: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    require(not output.exists(), f"runtime-root record already exists: {output}")
    output.write_text(json.dumps(_tree_record(root), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate_root_tree_record(work: Path, root_name: str, record_path: Path) -> dict[str, object]:
    expected = load_json_object(record_path, f"{root_name} tree record")
    require(set(expected) == {"directories", "files", "symlinks"}, f"{root_name} tree fields changed")
    observed = _tree_record(work / root_name)
    require(expected == observed, f"{root_name} materialized runtime root changed")
    return expected


def _validate_runtime_roots(
    work: Path,
    trees: Mapping[str, str],
    artifacts: Mapping[str, object],
    products: Mapping[str, object],
    oracle: Mapping[str, object],
) -> None:
    require(tuple(sorted(trees)) == tuple(sorted(ROOT_TREES)), "runtime-root roster changed")
    dynamic_manifest_path = validate_retained_artifact(
        work, artifacts[products["dynamic"]["manifest"]], "retained dynamic manifest"
    )
    dynamic_manifest = load_json_object(dynamic_manifest_path, "retained dynamic manifest")
    dynamic_files = _manifest_files(dynamic_manifest.get("files"), "retained dynamic manifest")
    dynamic_symlinks = dynamic_manifest.get("symlinks")
    require(isinstance(dynamic_symlinks, dict)
            and all(isinstance(name, str) and isinstance(target, str) for name, target in dynamic_symlinks.items()),
            "retained dynamic manifest symlinks changed")
    def parent_directories(names: Sequence[str]) -> set[str]:
        result: set[str] = set()
        for name in names:
            parent = Path(name).parent
            while parent != Path("."):
                result.add(parent.as_posix())
                parent = parent.parent
        return result
    for root_name in ROOT_TREES:
        binary = root_name.removesuffix("-root") + "-contract"
        require(binary in ELF_TYPES and binary != "contract.o", "runtime root has no linked contract")
        contract = artifacts[binary]
        tree_path_name = trees[root_name]
        require(tree_path_name == f"retained/runtime-roots/{root_name}.json", "runtime-root record path changed")
        tree_path = validate_retained_artifact(work, artifacts[tree_path_name], f"{root_name} tree")
        tree = _validate_root_tree_record(work, root_name, tree_path)
        files = tree["files"]
        symlinks = tree["symlinks"]
        require(isinstance(files, dict) and isinstance(symlinks, dict), "invalid retained root tree")
        if root_name.startswith("dynamic-"):
            expected_files = {
                **{name: {"sha256": digest, "size": (work / root_name / name).stat().st_size}
                   for name, digest in dynamic_files.items()},
                "share/crabc/manifest.json": {
                    "sha256": artifacts[products["dynamic"]["manifest"]]["sha256"],
                    "size": artifacts[products["dynamic"]["manifest"]]["size"],
                },
                "contract": {"sha256": contract["sha256"], "size": contract["size"]},
            }
            require(files == expected_files, f"{root_name} does not exactly materialize selected dynamic product files")
            require(symlinks == dynamic_symlinks, f"{root_name} dynamic product symlinks changed")
            require(tree["directories"] == sorted({
                *parent_directories([*expected_files, *symlinks]), "scratch",
            }), f"{root_name} dynamic root directories changed")
        else:
            expected_files = {
                "lib/ld-musl-x86_64.so.1": {"sha256": artifacts[oracle["shared"]]["sha256"],
                                               "size": artifacts[oracle["shared"]]["size"]},
                "usr/lib/libc.so": {"sha256": artifacts[oracle["shared"]]["sha256"],
                                      "size": artifacts[oracle["shared"]]["size"]},
                "contract": {"sha256": contract["sha256"], "size": contract["size"]},
            }
            require(files == expected_files and symlinks == {}, f"{root_name} musl runtime root changed")
            require(tree["directories"] == ["lib", "usr", "usr/lib"], f"{root_name} musl root directories changed")


def _resolved_linker_path(value: object, label: str) -> str:
    require(isinstance(value, dict) and set(value) == {"path", "sha256"},
            f"{label} resolved linker fields changed")
    path = value["path"]
    digest = value["sha256"]
    require(isinstance(path, str) and path.startswith("/") and "\x00" not in path,
            f"{label} resolved linker path changed")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"{label} resolved linker digest changed")
    return path


def _dynamic_product_root(products: Mapping[str, object]) -> str:
    dynamic = products["dynamic"]
    require(isinstance(dynamic, dict), "selected dynamic product is invalid")
    paths = dynamic["original_paths"]
    require(isinstance(paths, dict) and isinstance(paths.get("driver"), str),
            "selected dynamic driver path is invalid")
    return str(Path(paths["driver"]).parent.parent)


def _static_product_root(products: Mapping[str, object]) -> str:
    static = products["static"]
    require(isinstance(static, dict), "selected static product is invalid")
    paths = static["original_paths"]
    require(isinstance(paths, dict) and isinstance(paths.get("driver"), str),
            "selected static driver path is invalid")
    return str(Path(paths["driver"]).parent.parent)


def _validate_dynamic_link_receipt(
    path: Path, work: str, binary: str, artifacts: Mapping[str, object], products: Mapping[str, object],
    image_manifest: Mapping[str, object],
) -> None:
    """Reconstruct the sealed dynamic driver's ordinary link route exactly."""

    receipt = load_json_object(path, f"{binary} dynamic link receipt")
    expected_keys = {
        "application_dsos", "application_hash_style", "application_rpath", "application_runpath",
        "application_search_kind", "binding", "campaign_complete", "format", "input_receipts",
        "link_command", "link_trace", "manifest_sha256", "mode", "output_path", "output_sha256",
        "owned_runtime_inputs", "resolved_linker", "runtime_imports", "schema",
    }
    require(set(receipt) == expected_keys, f"{binary} dynamic link receipt fields changed")
    expected_mode = "pie" if binary.startswith("dynamic-pie-") else "exec"
    require(receipt["schema"] == 2 and receipt["format"] == "crabc-x86-64-owned-dynamic-sysroot-v1"
            and receipt["campaign_complete"] is False and receipt["mode"] == expected_mode
            and receipt["runtime_imports"] == [],
            f"{binary} dynamic link receipt boundary changed")
    require(receipt["application_dsos"] == {}
            and receipt["application_hash_style"] == "sysv"
            and receipt["application_rpath"] is None
            and receipt["application_runpath"] == "/usr/lib"
            and receipt["application_search_kind"] == "runpath"
            and receipt["binding"] == "now",
            f"{binary} dynamic application link policy changed")
    require(receipt["output_path"] == f"{work}/{binary}"
            and receipt["output_sha256"] == artifacts[binary]["sha256"],
            f"{binary} dynamic link receipt does not bind its ELF")

    dynamic = products["dynamic"]
    require(isinstance(dynamic, dict), "selected dynamic product is invalid")
    manifest_name = dynamic["manifest"]
    require(isinstance(manifest_name, str), "selected dynamic manifest path is invalid")
    manifest = load_json_object(work_path := path.parent / "retained/products/dynamic-manifest.json",
                                "retained dynamic manifest")
    dynamic_files = _manifest_files(manifest.get("files"), "retained dynamic manifest")
    require(receipt["manifest_sha256"] == artifacts[manifest_name]["sha256"],
            f"{binary} dynamic link receipt does not bind selected manifest")

    root = _dynamic_product_root(products)
    crt = "Scrt1.o" if expected_mode == "pie" else "crt1.o"
    runtime_files = [
        f"usr/lib/{crt}",
        "usr/lib/crabc-dynamic-attach.o",
        "usr/lib/crti.o",
        "usr/lib/crtn.o",
        "usr/lib/libc.so",
        "usr/lib/libcrabc-builtins.a",
    ]
    require(receipt["owned_runtime_inputs"] == sorted(runtime_files),
            f"{binary} dynamic runtime input roster changed")
    expected_inputs = {
        **{f"{root}/{relative}": digest for relative in runtime_files
           for digest in [dynamic_files.get(relative)] if digest is not None},
        f"{work}/contract.o": artifacts["contract.o"]["sha256"],
    }
    require(len(expected_inputs) == len(runtime_files) + 1,
            f"{binary} selected dynamic manifest lacks a link input")
    input_receipts = receipt["input_receipts"]
    require(isinstance(input_receipts, list) and len(input_receipts) == len(expected_inputs),
            f"{binary} dynamic link input receipt roster changed")
    observed_inputs: dict[str, str] = {}
    for item in input_receipts:
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}
                and isinstance(item["path"], str)
                and isinstance(item["sha256"], str)
                and item["path"] not in observed_inputs,
                f"{binary} dynamic link input receipt changed")
        observed_inputs[item["path"]] = item["sha256"]
    require(observed_inputs == expected_inputs,
            f"{binary} dynamic link receipt input binding changed")

    expected_trace = [
        f"{root}/usr/lib/{crt}",
        f"{root}/usr/lib/crabc-dynamic-attach.o",
        f"{root}/usr/lib/crti.o",
        f"{work}/contract.o",
        f"{root}/usr/lib/libc.so",
        f"{root}/usr/lib/crtn.o",
    ]
    require(receipt["link_trace"] == expected_trace,
            f"{binary} dynamic link trace changed")
    linker = _resolved_linker_path(receipt["resolved_linker"], binary)
    files = image_manifest.get("files")
    require(isinstance(files, dict) and receipt["resolved_linker"] == {
        "path": linker, "sha256": files.get(linker, {}).get("sha256"),
    }, f"{binary} dynamic linker is not the trusted pinned LLD")
    expected_link = [linker]
    if expected_mode == "pie":
        expected_link.append("-pie")
    expected_link += [
        "--hash-style=sysv", "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
        "--no-undefined", "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
        "--export-dynamic", "--dynamic-linker", INTERPRETER,
        f"{root}/usr/lib/{crt}", f"{root}/usr/lib/crabc-dynamic-attach.o",
        f"{root}/usr/lib/crti.o", f"{work}/contract.o", f"{root}/usr/lib/libc.so",
        f"{root}/usr/lib/libcrabc-builtins.a", f"{root}/usr/lib/crtn.o", "-o", f"{work}/{binary}",
    ]
    require(receipt["link_command"] == expected_link,
            f"{binary} dynamic linker command changed")


def _static_admitted_inputs(
    work: Path, work_path: str, binary: str, inputs: Mapping[str, Mapping[str, object]],
) -> dict[str, Path | bytes]:
    """Name every exact map owner needed by the finite static function proof."""

    entry = "static_crt1" if binary == "static-contract" else "static_rcrt1"
    admitted: dict[str, Path | bytes] = {
        f"{work_path}/contract.o": work / "contract.o",
        str(inputs[entry]["path"]): work / _input_copy_path(entry),
        str(inputs["static_crti"]["path"]): work / _input_copy_path("static_crti"),
        str(inputs["static_crtn"]["path"]): work / _input_copy_path("static_crtn"),
    }
    for input_name in ("static_libc", "static_builtins"):
        original = str(inputs[input_name]["path"])
        retained = work / _input_copy_path(input_name)
        try:
            members = list(archive_members(retained.read_bytes()))
        except (OSError, ValueError) as error:
            raise ReceiptError(f"retained {input_name} archive members differ") from error
        require(members, f"retained {input_name} archive has no members")
        for member, data in members:
            owner = f"{original}({member})"
            require(owner not in admitted, "static admitted owner is duplicated")
            admitted[owner] = data
    require(f"{inputs['static_libc']['path']}({PTHREAD_STATIC_MEMBER})" in admitted,
            "selected static archive omits the pthread provider object")
    return admitted


def _static_function_contracts(
    work_path: str, binary: str, inputs: Mapping[str, Mapping[str, object]],
) -> tuple[StaticFunctionContract, ...]:
    provider_owner = f"{inputs['static_libc']['path']}({PTHREAD_STATIC_MEMBER})"
    entry = "static_crt1" if binary == "static-contract" else "static_rcrt1"
    rows = [
        StaticFunctionContract("main", f"{work_path}/contract.o", "GLOBAL", "DEFAULT", "GLOBAL", "DEFAULT"),
        StaticFunctionContract("_start", str(inputs[entry]["path"]), "GLOBAL", "DEFAULT", "GLOBAL", "DEFAULT"),
    ]
    for public, provider in ALIASES:
        rows.extend((
            StaticFunctionContract(public, provider_owner, "WEAK", "DEFAULT", "WEAK", "DEFAULT"),
            StaticFunctionContract(provider, provider_owner, "GLOBAL", "HIDDEN", "LOCAL", "HIDDEN"),
        ))
    rows.extend(
        StaticFunctionContract(name, f"{work_path}/contract.o", "LOCAL", "DEFAULT", "LOCAL", "DEFAULT")
        for name in PROBE_HELPERS
    )
    return tuple(rows)


def _validate_static_link_receipt(
    work: Path, work_path: str, binary: str, artifacts: Mapping[str, object], products: Mapping[str, object],
    inputs: Mapping[str, Mapping[str, object]], image_manifest: Mapping[str, object],
) -> None:
    """Bind the static driver's own map/trace receipt to ordinary extraction."""

    receipt_name = f"{binary}.link.json"
    receipt = load_json_object(work / receipt_name, f"{binary} static link receipt")
    expected_keys = {
        "format", "input_receipts", "map", "mode", "output", "owned_link_contract",
        "resolved_linker", "schema", "target", "trace",
    }
    require(set(receipt) == expected_keys, f"{binary} static link receipt fields changed")
    require(receipt["schema"] == 1
            and receipt["format"] == "crabc-x86-64-sealed-static-driver-v1"
            and receipt["target"] == "x86_64-unknown-linux-musl",
            f"{binary} static link receipt identity changed")
    expected_mode = {
        "static-contract": {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o", "interpreter": "absent"},
        "static-pie-contract": {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o", "interpreter": "absent"},
    }[binary]
    require(receipt["mode"] == expected_mode, f"{binary} static link mode changed")
    output = receipt["output"]
    require(isinstance(output, dict) and set(output) == {"path", "sha256"}
            and output["path"] == f"{work_path}/{binary}"
            and output["sha256"] == artifacts[binary]["sha256"],
            f"{binary} static link receipt does not bind its ELF")
    for kind in ("map", "trace"):
        item = receipt[kind]
        expected_name = f"{binary}.link.{kind}" if kind == "trace" else f"{binary}.link.map"
        expected_path = work_path.removeprefix("/workspace/") + "/" + expected_name
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}
                and item["path"] == expected_path
                and item["sha256"] == artifacts[expected_name]["sha256"],
                f"{binary} static link {kind} identity changed")

    static = products["static"]
    require(isinstance(static, dict), "selected static product is invalid")
    manifest_name = static["manifest"]
    require(isinstance(manifest_name, str), "selected static manifest path is invalid")
    manifest = load_json_object(work / "retained/products/static-manifest.json", "retained static manifest")
    installed = manifest.get("installed")
    require(isinstance(installed, dict), "retained static manifest has no installed roster")
    static_files = _manifest_files(installed.get("files"), "retained static manifest")
    root = _static_product_root(products)
    crt = expected_mode["crt_object"]
    for input_name, installed_name in (
        ("static_crt1", "usr/lib/crt1.o"),
        ("static_rcrt1", "usr/lib/rcrt1.o"),
        ("static_crti", "usr/lib/crti.o"),
        ("static_crtn", "usr/lib/crtn.o"),
        ("static_builtins", "usr/lib/libcrabc-builtins.a"),
    ):
        require(static_files.get(installed_name) == inputs[input_name]["sha256"],
                f"{binary} selected static manifest does not bind {installed_name}")
    expected_inputs = {
        "crt-entry": (f"usr/lib/{crt}", static_files.get(f"usr/lib/{crt}")),
        "crt-prologue": ("usr/lib/crti.o", static_files.get("usr/lib/crti.o")),
        "libc": ("usr/lib/libc.a", artifacts[static["libc"]]["sha256"]),
        "builtins": ("usr/lib/libcrabc-builtins.a", static_files.get("usr/lib/libcrabc-builtins.a")),
        "crt-epilogue": ("usr/lib/crtn.o", static_files.get("usr/lib/crtn.o")),
        "application": (f"{work_path}/contract.o", artifacts["contract.o"]["sha256"]),
    }
    require(all(digest is not None for _, digest in expected_inputs.values()),
            f"{binary} selected static manifest lacks a link input")
    input_receipts = receipt["input_receipts"]
    require(isinstance(input_receipts, list) and len(input_receipts) == len(expected_inputs),
            f"{binary} static link input receipt roster changed")
    observed: dict[str, tuple[str, str]] = {}
    for item in input_receipts:
        require(isinstance(item, dict) and set(item) == {"path", "role", "sha256"}
                and all(isinstance(item[key], str) for key in ("path", "role", "sha256"))
                and item["role"] not in observed,
                f"{binary} static link input receipt changed")
        observed[item["role"]] = (item["path"], item["sha256"])
    require(observed == expected_inputs,
            f"{binary} static link receipt input binding changed")

    contract = ["ld.lld", "-static"]
    if binary == "static-pie-contract":
        contract.append("-pie")
    contract += [
        "--no-dynamic-linker", "--no-undefined", "--gc-sections", "-z", "relro", "-z", "now",
        "-e", "_start", f"{root}/usr/lib/{crt}", f"{root}/usr/lib/crti.o",
        "<application-objects>", f"{root}/usr/lib/libc.a", f"{root}/usr/lib/libcrabc-builtins.a",
        f"{root}/usr/lib/crtn.o", "-o", "<output>",
    ]
    require(receipt["owned_link_contract"] == contract,
            f"{binary} static ordinary-link contract changed")
    linker = _resolved_linker_path(receipt["resolved_linker"], binary)
    files = image_manifest.get("files")
    require(isinstance(files, dict) and receipt["resolved_linker"] == {
        "path": linker, "sha256": files.get(linker, {}).get("sha256"),
    }, f"{binary} static linker is not the trusted pinned LLD")
    trace_name = f"{binary}.link.trace"
    trace = (work / trace_name).read_text(encoding="utf-8").splitlines()
    require(trace.count(f"{work_path}/contract.o") == 1,
            f"{binary} static trace does not retain one contract object")
    require(any(line.startswith(f"{root}/usr/lib/libc.a(") for line in trace),
            f"{binary} static trace does not retain selected archive-member extraction")
    try:
        require_static_functions(
            work / f"{binary}.link.map", work / binary,
            _static_admitted_inputs(work, work_path, binary, inputs),
            _static_function_contracts(work_path, binary, inputs),
        )
    except StaticLinkAuthorityError as error:
        raise ReceiptError(f"{binary} selected static function authority differs: {error}") from error


def _coverage() -> dict[str, object]:
    return {
        "aliases": [
            {"public": public, "provider": provider, "placements": ["dynamic", "shared", "static"]}
            for public, provider in ALIASES
        ],
        "behavior": {
            "pthread_mutex_timedlock": ["past-deadline-timeout", "future-deadline-success"],
            "pthread_cond_timedwait": ["past-deadline-timeout", "signaled-success"],
            "pthread_tryjoin_np": ["busy-preserves-result"],
            "pthread_timedjoin_np": ["timeout-preserves-result", "success-result", "canceled-joiner-retains-target"],
            "timeout_seconds": TIMEOUT_SECONDS,
        },
        "limits": [
            "does-not-qualify-other-pthread-aliases-or-family-lifecycle",
            "does-not-promote-source-builder-argv-to-a-product-build-invocation",
        ],
    }


def _expected_retained_paths(work: Path) -> set[str]:
    paths = {
        "retained/oracle/compiler-wrapper",
        "retained/oracle/libc.so",
        "retained/oracle/libc.a",
        "retained/products/anchor-report.json",
        "retained/products/static-preparation.json",
        "retained/products/static-manifest.json",
        "retained/products/dynamic-manifest.json",
        "retained/products/dynamic-state.json",
        "retained/products/static-driver",
        "retained/products/static-libc.a",
        "retained/products/dynamic-driver",
        "retained/products/dynamic-libc.so",
        "retained/products/dynamic-loader",
        "retained/historical/input-identities.json",
    }
    paths.update(_input_copy_path(name) for name in INPUT_NAMES)
    paths.update(_collector_copy_path(name) for name in COLLECTOR_PATHS)
    paths.update(_image_copy_path(invocation) for invocation in trusted_image_manifest()["files"])
    paths.update(f"retained/source/{relative}" for relative in SOURCE_CONTRACT_PATHS)
    paths.update(f"retained/runtime-roots/{root}.json" for root in ROOT_TREES)
    paths.update(_preparation_retained_paths(work))
    return paths


def _artifact_map(work: Path) -> dict[str, dict[str, object]]:
    expected_direct = _direct_work_files()
    direct = {
        path.name for path in work.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    require(direct == expected_direct,
            f"raw pthread receipt file roster changed: missing={sorted(expected_direct - direct)} extra={sorted(direct - expected_direct)}")
    retained_root = work / "retained"
    observed_retained = {
        path.relative_to(work).as_posix()
        for path in retained_root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    expected_retained = _expected_retained_paths(work)
    git_objects = {name for name in observed_retained if name.startswith("retained/source/git-objects/")}
    require(git_objects and observed_retained == expected_retained | git_objects,
            f"retained pthread receipt file roster changed: missing={sorted(expected_retained - observed_retained)} extra={sorted(observed_retained - expected_retained - git_objects)}")
    expected = expected_direct | expected_retained | git_objects
    result: dict[str, dict[str, object]] = {}
    for relative in sorted(expected):
        path = work / relative
        require_regular(path, f"retained receipt artifact {relative}")
        result[relative] = artifact_record(work, path)
    return result


def _copy_input_set(work: Path, inputs: Mapping[str, Mapping[str, object]]) -> None:
    for name in INPUT_NAMES:
        source = Path(str(inputs[name]["path"]))
        _require_external_identity(source, inputs[name], name)
        _copy_regular(source, work / _input_copy_path(name), name)


def _collector_copy_path(name: str) -> str:
    paths = {
        "probe": "retained/collector/probe.c",
        "reader": "retained/collector/reader.py",
        "runner": "retained/collector/runner.sh",
        "syscall_authority": "retained/collector/owned-syscall-alias-authority.py",
        "static_authority": "retained/collector/owned-static-link-authority.py",
        "elf_authority": "retained/collector/loader-debug-abi-evidence.py",
        "image_manifest": "retained/collector/image-inputs.json",
    }
    require(name in paths, f"unknown collector authority source: {name}")
    return paths[name]


def _copy_collector_authority(
    work: Path, git_files: Mapping[str, tuple[int, bytes, bool]],
) -> None:
    """Copy exact current Git bytes for every reader dependency used at replay."""

    for name, relative in COLLECTOR_PATHS.items():
        mode, data, symlink = git_files.get(relative, (None, None, None))
        require(isinstance(mode, int) and isinstance(data, bytes) and symlink is False,
                f"collector authority Git source is unavailable: {relative}")
        destination = work / _collector_copy_path(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            require(name in COLLECTOR_INPUTS and not destination.is_symlink()
                    and destination.read_bytes() == data
                    and stat.S_IMODE(destination.stat().st_mode) == mode,
                    f"collector authority already exists: {relative}")
            continue
        destination.write_bytes(data)
        os.chmod(destination, mode)
        require(destination.read_bytes() == data and stat.S_IMODE(destination.stat().st_mode) == mode,
                f"collector authority copy changed: {relative}")


def _copy_source_contract(
    work: Path, root: Path, revision: str, git_files: Mapping[str, tuple[int, bytes, bool]],
) -> None:
    for relative in SOURCE_CONTRACT_PATHS:
        destination = work / "retained/source" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        require(not destination.exists() and not destination.is_symlink(),
                f"retained component source already exists: {relative}")
        mode, source, symlink = git_files.get(relative, (None, None, None))
        require(isinstance(mode, int) and isinstance(source, bytes) and symlink is False,
                f"selected source is missing {relative} at {revision}")
        destination.write_bytes(source)
        os.chmod(destination, mode)
        require_regular(destination, f"retained selected source {relative}")


def _selected_source_identity(root: Path, anchor: Mapping[str, object]) -> dict[str, object]:
    """Return the source identity that actually produced the selected products."""

    revision = anchor["source_commit"]
    source_sha256 = anchor["source_sha256"]
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
            "selected source revision is invalid")
    require(isinstance(source_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", source_sha256) is not None,
            "selected source digest is invalid")
    try:
        tree = _git(root, "rev-parse", revision + "^{tree}").decode("ascii").strip()
    except ReceiptError:
        raise ReceiptError("selected product source revision is unavailable in this checkout") from None
    require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "selected source tree is invalid")
    return {"revision": revision, "tree": tree, "source_sha256": source_sha256}


def _materialize_selected_source(
    destination: Path, files: Mapping[str, tuple[int, bytes, bool]],
) -> None:
    """Write the sealed selected tree for the existing preparation owner.

    The owner needs a physical checkout-shaped root to replay its package
    checks. Every source node still comes from source_tree's retained
    commit/tree/blob authority; this never reads a current checkout file.
    """

    require(not destination.exists() and not destination.is_symlink(),
            "selected source materialization destination already exists")
    destination.mkdir()
    for relative, (mode, data, symlink) in sorted(files.items()):
        target = destination / _safe_relative(relative, "selected source materialization")
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists() and not target.is_symlink(),
                f"duplicate selected source materialization path: {relative}")
        if symlink:
            target.symlink_to(os.fsdecode(data))
        else:
            target.write_bytes(data)
            os.chmod(target, mode)
    for relative, (mode, data, symlink) in files.items():
        target = destination / relative
        if symlink:
            require(target.is_symlink() and os.fsencode(os.readlink(target)) == data,
                    f"selected source symlink changed: {relative}")
        else:
            require_regular(target, f"selected source materialization {relative}")
            require(target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == mode,
                    f"selected source materialization changed: {relative}")


def _canonical_static_preparation(
    work: Path, source: Mapping[str, object], inputs: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """Replay the selected full preparation with its established owner.

    The preparation owner retains all primary/reproduction/extracted products,
    package archives, source seals, and each command sidecar. Its source
    callback is replaced only with the same full selected Git-tree identity
    used by this receipt; invoking the callback never grants the collector
    source authority over selected-product source.
    """

    work = work.resolve(strict=True)
    revision = source["revision"]
    require(isinstance(revision, str), "selected source revision is invalid")
    derived, files = source_tree(work / "retained", revision)
    expected_source = {
        "revision": source["revision"],
        "content_sha256": source["source_sha256"],
    }
    require(derived == expected_source, "selected Git tree differs before preparation replay")
    retained = work / PREPARATION_RETAINED_ROOT / "preparation.json"
    input_copy = work / _input_copy_path("static_preparation")
    require(retained.read_bytes() == input_copy.read_bytes()
            and stat.S_IMODE(retained.stat().st_mode) == stat.S_IMODE(input_copy.stat().st_mode),
            "full retained preparation does not match captured preparation input")
    record = load_json_object(retained, "retained static preparation")
    relative_work = _safe_relative(record.get("work"), "retained static preparation work")
    require(relative_work.parts[:2] == (".work", "x86_64"),
            "retained static preparation work path changed")
    with tempfile.TemporaryDirectory(prefix=".pthread-preparation-replay.", dir=work.parent) as temporary:
        root = Path(temporary) / "selected-source"
        _materialize_selected_source(root, files)
        preparation = root / relative_work
        _copy_tree(work / PREPARATION_RETAINED_ROOT, preparation, "replayed static preparation")
        original_source_identity = static_products.source_identity
        def sealed_source_identity(candidate: Path) -> dict[str, object]:
            require(candidate == root, "static preparation owner escaped selected source root")
            return dict(derived)
        try:
            static_products.source_identity = sealed_source_identity
            observed = static_products.validate_receipt(root, preparation / "preparation.json")
        finally:
            static_products.source_identity = original_source_identity
    require(isinstance(observed, dict), "static preparation owner produced no record")
    primary = observed.get("products", {}).get("primary")
    require(isinstance(primary, dict)
            and primary.get("tree", {}).get("usr/lib/libc.a", {}).get("sha256")
            == inputs["static_libc"]["sha256"],
            "canonical static preparation primary does not bind selected archive")
    return observed


def _copy_product_sidecars(work: Path, product: Mapping[str, object], inputs: Mapping[str, Mapping[str, object]]) -> None:
    for source, destination, label in (
        (product["static_manifest_path"], "retained/products/static-manifest.json", "static manifest"),
        (product["dynamic_manifest_path"], "retained/products/dynamic-manifest.json", "dynamic manifest"),
        (product["dynamic_state_path"], "retained/products/dynamic-state.json", "dynamic product state"),
    ):
        _copy_regular(Path(source), work / destination, label)


def _copy_historical(work: Path, historical_inputs: Path) -> None:
    _load_historical_inputs(historical_inputs)
    _copy_regular(historical_inputs, work / "retained/historical/input-identities.json", "historical input identities")


def _source_contract_records(work: Path) -> dict[str, object]:
    source_files = {relative: artifact_record(work, work / "retained/source" / relative)
                    for relative in SOURCE_CONTRACT_PATHS}
    digest = hashlib.sha256()
    for relative, record in source_files.items():
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(bytes.fromhex(str(record["sha256"])))
    return {"files": source_files, "component_sha256": digest.hexdigest()}


def _validate_selected_source(work: Path, source: Mapping[str, object], artifacts: Mapping[str, object]) -> None:
    require(set(source) == {"revision", "tree", "source_sha256", "component_sha256", "files"},
            "selected source fields changed")
    identity = _validate_source_identity({key: source[key] for key in ("revision", "tree", "source_sha256")},
                                        "selected source")
    derived, git_files = source_tree(work / "retained", identity["revision"])
    require(derived == {"revision": identity["revision"], "content_sha256": identity["source_sha256"]},
            "selected source Git objects differ")
    files = source["files"]
    require(isinstance(files, dict) and tuple(sorted(files)) == tuple(sorted(SOURCE_CONTRACT_PATHS)),
            "selected source file roster changed")
    digest = hashlib.sha256()
    for relative in SOURCE_CONTRACT_PATHS:
        path_name = f"retained/source/{relative}"
        require(files[relative] == artifacts[path_name], f"selected source record changed: {relative}")
        retained = validate_retained_artifact(work, artifacts[path_name], f"selected source {relative}")
        require(relative in git_files and retained.read_bytes() == git_files[relative][1]
                and stat.S_IMODE(retained.stat().st_mode) == git_files[relative][0],
                f"selected source Git bytes or mode differ: {relative}")
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(bytes.fromhex(str(artifacts[path_name]["sha256"])))
    require(digest.hexdigest() == source["component_sha256"], "selected source component digest changed")


def _validate_collector(work: Path, collector: Mapping[str, object], artifacts: Mapping[str, object], inputs: Mapping[str, Mapping[str, object]]) -> None:
    require(set(collector) == {"source_before", "source_after", "files"}, "collector fields changed")
    before = _validate_source_identity(collector["source_before"], "collector source before")
    after = _validate_source_identity(collector["source_after"], "collector source after")
    require(before == after, "collector source changed during collection")
    snapshot_path = validate_retained_artifact(work, artifacts["source-before.json"], "source-before snapshot")
    require(_load_source_snapshot(snapshot_path) == before, "retained source-before snapshot changed")
    derived, git_files = source_tree(work / "retained", before["revision"])
    require(derived == {"revision": before["revision"], "content_sha256": before["source_sha256"]},
            "collector source Git objects differ")
    files = collector["files"]
    require(isinstance(files, dict) and tuple(sorted(files)) == tuple(sorted(COLLECTOR_PATHS)),
            "collector source roster changed")
    for name, tracked in COLLECTOR_PATHS.items():
        relative = _collector_copy_path(name)
        require(files[name] == artifacts[relative], f"collector {name} record changed")
        retained = validate_retained_artifact(work, artifacts[relative], f"collector {name}")
        require(tracked in git_files and retained.read_bytes() == git_files[tracked][1]
                and stat.S_IMODE(retained.stat().st_mode) == git_files[tracked][0],
                f"collector {name} Git bytes or mode differ")
        if name in COLLECTOR_INPUTS:
            require(artifacts[relative]["sha256"] == inputs[name]["sha256"]
                    and artifacts[relative]["size"] == inputs[name]["size"]
                    and artifacts[relative]["mode"] == inputs[name]["mode"],
                    f"collector {name} differs from captured input")


def _validate_selected_products(
    work: Path,
    selected: Mapping[str, object],
    artifacts: Mapping[str, object],
    source: Mapping[str, object],
    inputs: Mapping[str, Mapping[str, object]],
) -> None:
    require(set(selected) == {"anchor", "static", "dynamic"}, "selected product fields changed")
    anchor_meta = selected["anchor"]
    require(isinstance(anchor_meta, dict)
            and set(anchor_meta) == {"report", "schema", "source_commit", "source_sha256"},
            "selected product anchor metadata changed")
    require(anchor_meta["report"] == "retained/products/anchor-report.json", "selected anchor path changed")
    anchor_path = validate_retained_artifact(work, artifacts[anchor_meta["report"]], "selected product anchor")
    anchor = load_json_object(anchor_path, "retained selected product anchor")
    require(anchor_meta["schema"] == "crabc.x86_64-loader-debug-crt-abi/v1"
            and anchor.get("schema") == anchor_meta["schema"]
            and anchor.get("status") == "component-verified"
            and anchor.get("public_support") is False and anchor.get("family_complete") is False,
            "retained selected product anchor boundary changed")
    require(anchor_meta["source_commit"] == source["revision"]
            and anchor_meta["source_sha256"] == source["source_sha256"]
            and anchor.get("source_commit") == source["revision"]
            and anchor.get("source_sha256") == source["source_sha256"],
            "retained selected products do not match selected product source")

    static = selected["static"]
    dynamic = selected["dynamic"]
    require(isinstance(static, dict) and set(static) == {"manifest", "driver", "libc", "original_paths"},
            "selected static product fields changed")
    require(isinstance(dynamic, dict) and set(dynamic) == {"manifest", "state", "driver", "libc", "loader", "original_paths"},
            "selected dynamic product fields changed")
    require(static["manifest"] == "retained/products/static-manifest.json"
            and static["driver"] == "retained/products/static-driver"
            and static["libc"] == "retained/products/static-libc.a", "selected static artifact paths changed")
    require(dynamic["manifest"] == "retained/products/dynamic-manifest.json"
            and dynamic["state"] == "retained/products/dynamic-state.json"
            and dynamic["driver"] == "retained/products/dynamic-driver"
            and dynamic["libc"] == "retained/products/dynamic-libc.so"
            and dynamic["loader"] == "retained/products/dynamic-loader", "selected dynamic artifact paths changed")
    for value in (static["original_paths"], dynamic["original_paths"]):
        require(isinstance(value, dict) and all(isinstance(item, str) and item.startswith("/") for item in value.values()),
                "selected product original paths changed")
    require(set(static["original_paths"]) == {"driver", "libc"}
            and set(dynamic["original_paths"]) == {"driver", "libc", "loader"},
            "selected product original path roster changed")
    require(static["original_paths"] == {
        "driver": inputs["static_driver"]["path"], "libc": inputs["static_libc"]["path"],
    } and dynamic["original_paths"] == {
        "driver": inputs["dynamic_driver"]["path"], "libc": inputs["dynamic_libc"]["path"],
        "loader": inputs["dynamic_loader"]["path"],
    }, "selected product original paths differ from captured product inputs")
    for relative in (static["manifest"], static["driver"], static["libc"], dynamic["manifest"], dynamic["state"], dynamic["driver"], dynamic["libc"], dynamic["loader"]):
        validate_retained_artifact(work, artifacts[relative], f"selected product {relative}")

    preparation = load_json_object(work / "retained/products/static-preparation.json", "retained static preparation")
    require(preparation.get("schema") == "crabc.x86_64-owned-posix-static-preparation/v1"
            and preparation.get("source", {}).get("revision") == source["revision"]
            and preparation.get("source", {}).get("content_sha256") == source["source_sha256"],
            "retained static preparation source changed")
    require(preparation.get("steps", {}).get("primary-build", {}).get("exit_status") == 0
            and preparation.get("products", {}).get("primary", {}).get("tree", {}).get("usr/lib/libc.a", {}).get("sha256") == artifacts[static["libc"]]["sha256"],
            "retained static preparation primary build changed")
    static_manifest = load_json_object(work / str(static["manifest"]), "retained static manifest")
    dynamic_manifest = load_json_object(work / str(dynamic["manifest"]), "retained dynamic manifest")
    dynamic_state = load_json_object(work / str(dynamic["state"]), "retained dynamic state")
    require(static_manifest.get("schema") == 1
            and static_manifest.get("format") == "crabc-x86-64-owned-static-sysroot-v1", "retained static manifest changed")
    require(dynamic_manifest.get("schema") == 1
            and dynamic_manifest.get("format") == "crabc-x86-64-owned-dynamic-sysroot-v1", "retained dynamic manifest changed")
    static_files = _manifest_files(static_manifest["installed"]["files"], "retained static manifest")
    dynamic_files = _manifest_files(dynamic_manifest["files"], "retained dynamic manifest")
    _validate_dynamic_materialization_state(
        dynamic_state, source["source_sha256"], dynamic_files, "retained dynamic product state"
    )
    require(dynamic_files.get(DYNAMIC_STATE_PATH) == artifacts[dynamic["state"]]["sha256"],
            "retained dynamic manifest does not seal dynamic materialization state")
    for manifest_files, relative, expected_name in (
        (static_files, static["driver"], "bin/crabc-cc"),
        (static_files, static["libc"], "usr/lib/libc.a"),
        (dynamic_files, dynamic["driver"], "bin/crabc-cc-dynamic"),
        (dynamic_files, dynamic["libc"], "usr/lib/libc.so"),
        (dynamic_files, dynamic["loader"], "lib/ld-crabc-x86_64.so.1"),
    ):
        require(manifest_files.get(expected_name) == artifacts[relative]["sha256"],
                f"retained manifest does not seal {expected_name}")
    for anchor_name, relative in (
        ("static-manifest", static["manifest"]),
        ("dynamic-manifest", dynamic["manifest"]),
        ("dynamic-state", dynamic["state"]),
        ("candidate-libc", dynamic["libc"]),
        ("candidate-loader", dynamic["loader"]),
    ):
        anchor_item = _anchor_artifact(anchor, anchor_name, anchor_name)
        require(_same_external_record(anchor_item, artifacts[relative]),
                f"retained product anchor does not bind {anchor_name}")


def _validate_oracle(work: Path, oracle: Mapping[str, object], artifacts: Mapping[str, object], selected: Mapping[str, object]) -> None:
    require(set(oracle) == {"release", "source_commit", "compiler", "shared", "archive"},
            "oracle fields changed")
    require(oracle["release"] == MUSL_RELEASE and oracle["source_commit"] == MUSL_SOURCE_COMMIT,
            "pinned musl oracle identity changed")
    for key, relative in (
        ("compiler", "retained/oracle/compiler-wrapper"),
        ("shared", "retained/oracle/libc.so"),
        ("archive", "retained/oracle/libc.a"),
    ):
        require(oracle[key] == relative, f"oracle {key} artifact path changed")
        validate_retained_artifact(work, artifacts[relative], f"oracle {key}")
    anchor_path = work / str(selected["anchor"]["report"])
    anchor = load_json_object(anchor_path, "retained selected product anchor")
    anchor_oracle = anchor.get("oracle")
    require(isinstance(anchor_oracle, dict)
            and anchor_oracle.get("version") == MUSL_RELEASE
            and anchor_oracle.get("runtime_sha256") == artifacts[oracle["shared"]]["sha256"]
            and anchor_oracle.get("compiler_wrapper_sha256") == artifacts[oracle["compiler"]]["sha256"],
            "selected product anchor does not bind pinned shared oracle")


def _validate_historical(work: Path, historical: Mapping[str, object], artifacts: Mapping[str, object], inputs: Mapping[str, Mapping[str, object]], source: Mapping[str, object]) -> None:
    require(set(historical) == {"role", "used_for_selected_products", "source_commit", "source_tree", "input_identities"},
            "historical evidence fields changed")
    require(historical["role"] == "pre-receipt-pthread-alias-matrix"
            and historical["used_for_selected_products"] is False,
            "historical evidence role changed")
    for key in ("source_commit", "source_tree"):
        require(isinstance(historical[key], str) and re.fullmatch(r"[0-9a-f]{40}", historical[key]) is not None,
                f"historical evidence {key} is invalid")
    require(historical["source_commit"] != source["revision"], "historical evidence is confused with selected product source")
    relative = "retained/historical/input-identities.json"
    require(historical["input_identities"] == relative, "historical input path changed")
    path = validate_retained_artifact(work, artifacts[relative], "historical input identities")
    old = _load_historical_inputs(path)
    require(old["static_libc"]["sha256"] != inputs["static_libc"]["sha256"]
            and old["dynamic_libc"]["sha256"] != inputs["dynamic_libc"]["sha256"],
            "historical evidence is confused with selected products")


def _validate_inputs(work: Path, report_inputs: Mapping[str, object], artifacts: Mapping[str, object]) -> dict[str, dict[str, object]]:
    require(isinstance(report_inputs, dict) and tuple(sorted(report_inputs)) == tuple(sorted(INPUT_NAMES)),
            "report input roster changed")
    raw_path = validate_retained_artifact(work, artifacts["input-identities.json"], "input identities")
    inputs = _load_inputs(raw_path)
    for name in INPUT_NAMES:
        entry = report_inputs[name]
        require(isinstance(entry, dict) and set(entry) == {"original_path", "retained"},
                f"report input {name} fields changed")
        require(entry["original_path"] == inputs[name]["path"], f"report input {name} path changed")
        expected_copy = _input_copy_path(name)
        require(entry["retained"] == expected_copy, f"report input {name} retained path changed")
        retained = validate_retained_artifact(work, artifacts[expected_copy], f"retained input {name}")
        require(artifacts[expected_copy]["sha256"] == inputs[name]["sha256"]
                and artifacts[expected_copy]["size"] == inputs[name]["size"]
                and artifacts[expected_copy]["mode"] == inputs[name]["mode"],
                f"retained input {name} differs from captured input")
        require(retained == work / expected_copy, f"retained input {name} escaped receipt root")
    return inputs


def _validate_commands(work: Path, commands: Mapping[str, object], artifacts: Mapping[str, object], inputs: Mapping[str, Mapping[str, object],], collection: Mapping[str, object]) -> None:
    require(tuple(sorted(commands)) == tuple(sorted(COMMANDS)), "command roster changed")
    require(set(collection) == {"work_path", "timeout_seconds"}, "collection context fields changed")
    work_path = collection["work_path"]
    require(isinstance(work_path, str) and work_path.startswith("/workspace/.work/") and "\x00" not in work_path,
            "collection work path is invalid")
    require(collection["timeout_seconds"] == TIMEOUT_SECONDS, "collection timeout changed")
    input_paths = {
        "probe": str(inputs["probe"]["path"]),
        "dynamic_driver": str(inputs["dynamic_driver"]["path"]),
        "static_driver": str(inputs["static_driver"]["path"]),
        "oracle_compiler": str(inputs["oracle_compiler"]["path"]),
    }
    for name in COMMANDS:
        row = commands[name]
        require(isinstance(row, dict) and set(row) == {"argv", "status", "stdout", "stderr"},
                f"{name} command fields changed")
        expected_paths = {
            "argv": f"{name}.argv.json",
            "status": f"{name}.status",
            "stdout": f"{name}.stdout",
            "stderr": f"{name}.stderr",
        }
        require(row == expected_paths, f"{name} command artifact paths changed")
        argv_path = validate_retained_artifact(work, artifacts[row["argv"]], f"{name} argv")
        validate_retained_artifact(work, artifacts[row["status"]], f"{name} status")
        stdout = validate_retained_artifact(work, artifacts[row["stdout"]], f"{name} stdout")
        stderr = validate_retained_artifact(work, artifacts[row["stderr"]], f"{name} stderr")
        require((work / row["status"]).read_bytes() == b"0\n", f"{name} exit status changed")
        validate_command_argv(name, _argv(argv_path, f"{name} argv"), work_path, input_paths)
        if name in RUNTIME_COMMANDS:
            require(stdout.read_bytes() == SUCCESS_TRANSCRIPT and stderr.read_bytes() == b"",
                    f"{name} runtime transcript changed")
        else:
            require(stdout.read_bytes() == b"" and stderr.read_bytes() == b"",
                    f"{name} diagnostic stream changed")
        if name in LINK_MAPS:
            map_path = work / LINK_MAPS[name]
            validate_retained_artifact(work, artifacts[map_path.name], f"{name} link map")
            require(map_path.stat().st_size > 0, f"{name} retained link map is empty")


def _validate_coverage(value: object) -> None:
    require(value == _coverage(), "covered pthread timed feature obligations changed")


def validate_report(report_path: Path) -> dict[str, object]:
    """Replay one receipt from retained bytes without a compiler or ELF tool."""

    report_path = report_path.resolve(strict=True)
    work = report_path.parent
    report = load_json_object(report_path, "pthread timed feature receipt")
    expected_keys = {
        "schema", "status", "component", "public_support", "family_complete", "promotion_ready",
        "collection", "execution", "selected_source", "collector", "inputs", "selected_products", "static_preparation", "oracle",
        "historical_evidence", "coverage", "feature_source", "product_input_modes", "artifacts", "commands", "elf_headers",
        "alias_observations", "final_extraction", "runtime_roots", "image_inputs",
    }
    require(set(report) == expected_keys, "pthread alias receipt fields changed")
    require(report["schema"] == SCHEMA and report["status"] == STATUS and report["component"] == COMPONENT,
            "pthread alias receipt schema changed")
    require(report["public_support"] is False and report["family_complete"] is False
            and report["promotion_ready"] is False, "pthread alias receipt crossed its component boundary")
    artifacts = report["artifacts"]
    require(isinstance(artifacts, dict), "pthread alias artifacts are invalid")
    execution = report["execution"]
    require(execution == {
        "record": "execution-environment.json",
        "schema": EXECUTION_SCHEMA,
        "stdin": "/dev/null",
    }, "pthread execution boundary changed")
    git_objects = {
        relative for relative in artifacts
        if relative.startswith("retained/source/git-objects/")
    }
    require(git_objects and all(re.fullmatch(r"retained/source/git-objects/[0-9a-f]{40}", relative)
                                is not None for relative in git_objects)
            and set(artifacts) == _direct_work_files() | _expected_retained_paths(work) | git_objects,
            "pthread alias artifact roster changed")
    for relative, record in artifacts.items():
        require(relative == record.get("path") if isinstance(record, dict) else False,
                f"artifact key/path mismatch: {relative}")
        validate_retained_artifact(work, record, f"artifact {relative}")
    execution_record = load_json_object(work / "execution-environment.json", "pthread execution record")
    require(execution_record == {
        "environment": EXECUTION_ENVIRONMENT,
        "schema": EXECUTION_SCHEMA,
        "stdin": "/dev/null",
    }, "retained pthread execution environment changed")
    source = report["selected_source"]
    require(isinstance(source, dict), "selected product source is invalid")
    _validate_selected_source(work, source, artifacts)
    inputs = _validate_inputs(work, report["inputs"], artifacts)
    require(report["product_input_modes"] == product_evidence.link_input_mode_projection(),
            "retained selected product mode projection changed")
    _validate_link_input_modes(inputs)
    collector = report["collector"]
    require(isinstance(collector, dict), "collector is invalid")
    _validate_collector(work, collector, artifacts, inputs)
    _, collector_git_files = source_tree(work / "retained", str(collector["source_before"]["revision"]))
    image_manifest = _validate_image_inputs(work, report["image_inputs"], artifacts, collector_git_files)
    # Raw readelf text is a diagnostic view only; derive it from retained ELF/archive bytes.
    for stream, artifact, logical, tables in (
        ("musl-dynamic-symbols.txt", "retained/oracle/libc.so", str(inputs["musl_shared"]["path"]), {".dynsym"}),
        ("candidate-dynamic-symbols.txt", "retained/products/dynamic-libc.so", str(inputs["dynamic_libc"]["path"]), {".dynsym"}),
        ("musl-shared-symbols.txt", "retained/oracle/libc.so", str(inputs["musl_shared"]["path"]), {".dynsym", ".symtab"}),
        ("candidate-shared-symbols.txt", "retained/products/dynamic-libc.so", str(inputs["dynamic_libc"]["path"]), {".dynsym", ".symtab"}),
        ("musl-static-symbols.txt", "retained/oracle/libc.a", str(inputs["musl_archive"]["path"]), {".symtab"}),
        ("candidate-static-symbols.txt", "retained/products/static-libc.a", str(inputs["static_libc"]["path"]), {".symtab"}),
    ):
        require_symbol_stream(work / stream, work / artifact, logical, tables)
    for stream, binary, tables in (
        ("static-contract.symbols.txt", "static-contract", {".symtab"}),
        ("static-pie-contract.symbols.txt", "static-pie-contract", {".dynsym", ".symtab"}),
        ("dynamic-pie-contract.symbols.txt", "dynamic-pie-contract", {".dynsym", ".symtab"}),
        ("dynamic-non-pie-contract.symbols.txt", "dynamic-non-pie-contract", {".dynsym", ".symtab"}),
    ):
        require_symbol_stream(work / stream, work / binary, "", tables)
    require_archive_relocation_stream(
        work / "musl-static-relocations.txt", work / "retained/oracle/libc.a", str(inputs["musl_archive"]["path"]),
    )
    require_archive_relocation_stream(
        work / "candidate-static-relocations.txt", work / "retained/products/static-libc.a", str(inputs["static_libc"]["path"]),
    )
    require((work / "contract-compile.stdout").read_bytes() == b"", "compile stdout changed")
    selected = report["selected_products"]
    require(isinstance(selected, dict), "selected products are invalid")
    _validate_selected_products(work, selected, artifacts, source, inputs)
    preparation = report["static_preparation"]
    require(preparation == {
        "retained_root": PREPARATION_RETAINED_ROOT,
        "record": f"{PREPARATION_RETAINED_ROOT}/preparation.json",
        "owner": "compat/x86_64/owned_posix_static_products.py",
    }, "static preparation replay boundary changed")
    _canonical_static_preparation(work, source, inputs)
    oracle = report["oracle"]
    require(isinstance(oracle, dict), "oracle is invalid")
    _validate_oracle(work, oracle, artifacts, selected)
    historical = report["historical_evidence"]
    require(isinstance(historical, dict), "historical evidence is invalid")
    _validate_historical(work, historical, artifacts, inputs, source)
    _validate_coverage(report["coverage"])
    commands = report["commands"]
    require(isinstance(commands, dict), "commands are invalid")
    collection = report["collection"]
    require(isinstance(collection, dict), "collection context is invalid")
    _validate_commands(work, commands, artifacts, inputs, collection)
    require(report["elf_headers"] == evaluate_elf_headers(work), "retained ELF header observations changed")
    require(report["alias_observations"] == evaluate_alias_contract(work),
            "retained pthread alias observations changed")
    require(report["final_extraction"] == evaluate_final_extraction(work),
            "retained pthread final extraction differs")
    require(report["feature_source"] == evaluate_feature_source(work / "retained/source"),
            "retained pthread timed feature source differs")
    roots = report["runtime_roots"]
    require(isinstance(roots, dict), "runtime roots are invalid")
    _validate_runtime_roots(work, roots, artifacts, selected, oracle)
    for binary in ("dynamic-pie-contract", "dynamic-non-pie-contract"):
        _validate_dynamic_link_receipt(
            work / f"{binary}.crabc-link.json", str(collection["work_path"]), binary, artifacts, selected,
            image_manifest,
        )
        try:
            require_pthread_timed_probe_functions(work / "contract.o", work / binary)
        except PthreadTimedDynamicAuthorityError as error:
            raise ReceiptError(f"{binary} pthread probe function authority differs: {error}") from error
    for binary in ("static-contract", "static-pie-contract"):
        _validate_static_link_receipt(
            work, str(collection["work_path"]), binary, artifacts, selected, inputs, image_manifest,
        )
    return report


def collect_report(
    work: Path,
    root: Path,
    product_report: Path,
    historical_inputs: Path,
    historical_source_commit: str,
) -> Path:
    """Seal a completed focused runner work directory into one replay receipt."""

    work = work.resolve(strict=True)
    root = root.resolve(strict=True)
    require(not (work / "report.json").exists(), "pthread receipt report already exists")
    before = _load_source_snapshot(work / "source-before.json")
    current = source_identity(root)
    require(before == current, "source changed between runner start and receipt collection")
    inputs = _load_inputs(work / "input-identities.json")
    require(Path(str(inputs["product_report"]["path"])).resolve(strict=True) == product_report.resolve(strict=True),
            "collector product anchor path differs from captured input")
    product = _validate_product_anchor(product_report, inputs)
    _validate_link_input_modes(inputs)
    _validate_current_product_links(work, inputs)
    selected_source = _selected_source_identity(root, product["anchor"])
    trusted_image = trusted_image_manifest()
    require(live_image_manifest() == trusted_image, "live image inputs differ from trusted pthread image manifest")
    capture_git_objects(root, work / "retained", [str(selected_source["revision"]), str(current["revision"])])
    _, selected_git_files = source_tree(work / "retained", str(selected_source["revision"]))
    _, collector_git_files = source_tree(work / "retained", str(current["revision"]))
    _copy_input_set(work, inputs)
    _copy_static_preparation_cohort(work, inputs)
    _copy_collector_authority(work, collector_git_files)
    _copy_image_inputs(work, trusted_image)
    _copy_source_contract(work, root, str(selected_source["revision"]), selected_git_files)
    _copy_product_sidecars(work, product, inputs)
    _canonical_static_preparation(work, selected_source, inputs)
    _copy_historical(work, historical_inputs.resolve(strict=True))
    require(re.fullmatch(r"[0-9a-f]{40}", historical_source_commit) is not None,
            "historical source commit is invalid")
    try:
        historical_tree = _git(root, "rev-parse", historical_source_commit + "^{tree}").decode("ascii").strip()
    except ReceiptError:
        raise ReceiptError("historical source commit is unavailable in this checkout") from None
    require(historical_source_commit != current["revision"], "historical source must differ from current collection source")
    for root_name in ROOT_TREES:
        _write_tree_record(work / root_name, work / f"retained/runtime-roots/{root_name}.json")

    artifacts = _artifact_map(work)
    source_records = _source_contract_records(work)
    report = {
        "schema": SCHEMA,
        "status": STATUS,
        "component": COMPONENT,
        "public_support": False,
        "family_complete": False,
        "promotion_ready": False,
        "collection": {"work_path": str(work), "timeout_seconds": TIMEOUT_SECONDS},
        "execution": {
            "record": "execution-environment.json",
            "schema": EXECUTION_SCHEMA,
            "stdin": "/dev/null",
        },
        "selected_source": {**selected_source, **source_records},
        "collector": {
            "source_before": before,
            "source_after": current,
            "files": {name: artifacts[_collector_copy_path(name)] for name in COLLECTOR_PATHS},
        },
        "image_inputs": {
            invocation: {**record, "retained": _image_copy_path(invocation)}
            for invocation, record in trusted_image["files"].items()
        },
        "inputs": {
            name: {"original_path": inputs[name]["path"], "retained": _input_copy_path(name)}
            for name in INPUT_NAMES
        },
        "selected_products": {
            "anchor": {
                "report": "retained/products/anchor-report.json",
                "schema": product["anchor"]["schema"],
                "source_commit": product["anchor"]["source_commit"],
                "source_sha256": product["anchor"]["source_sha256"],
            },
            "static": {
                "manifest": "retained/products/static-manifest.json",
                "driver": "retained/products/static-driver",
                "libc": "retained/products/static-libc.a",
                "original_paths": {
                    "driver": inputs["static_driver"]["path"],
                    "libc": inputs["static_libc"]["path"],
                },
            },
            "dynamic": {
                "manifest": "retained/products/dynamic-manifest.json",
                "state": "retained/products/dynamic-state.json",
                "driver": "retained/products/dynamic-driver",
                "libc": "retained/products/dynamic-libc.so",
                "loader": "retained/products/dynamic-loader",
                "original_paths": {
                    "driver": inputs["dynamic_driver"]["path"],
                    "libc": inputs["dynamic_libc"]["path"],
                    "loader": inputs["dynamic_loader"]["path"],
                },
            },
        },
        "static_preparation": {
            "retained_root": PREPARATION_RETAINED_ROOT,
            "record": f"{PREPARATION_RETAINED_ROOT}/preparation.json",
            "owner": "compat/x86_64/owned_posix_static_products.py",
        },
        "product_input_modes": product_evidence.link_input_mode_projection(),
        "oracle": {
            "release": MUSL_RELEASE,
            "source_commit": MUSL_SOURCE_COMMIT,
            "compiler": "retained/oracle/compiler-wrapper",
            "shared": "retained/oracle/libc.so",
            "archive": "retained/oracle/libc.a",
        },
        "historical_evidence": {
            "role": "pre-receipt-pthread-alias-matrix",
            "used_for_selected_products": False,
            "source_commit": historical_source_commit,
            "source_tree": historical_tree,
            "input_identities": "retained/historical/input-identities.json",
        },
        "coverage": _coverage(),
        "feature_source": evaluate_feature_source(root),
        "artifacts": artifacts,
        "commands": {
            name: {
                "argv": f"{name}.argv.json",
                "status": f"{name}.status",
                "stdout": f"{name}.stdout",
                "stderr": f"{name}.stderr",
            }
            for name in COMMANDS
        },
        "elf_headers": evaluate_elf_headers(work),
        "alias_observations": evaluate_alias_contract(work),
        "final_extraction": evaluate_final_extraction(work),
        "runtime_roots": {
            name: f"retained/runtime-roots/{name}.json" for name in ROOT_TREES
        },
    }
    output = work / "report.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_report(output)
    return output


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--capture-source", action="store_true")
    action.add_argument("--check-work", action="store_true")
    action.add_argument("--collect-report", action="store_true")
    action.add_argument("--validate-report", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--product-report", type=Path)
    parser.add_argument("--historical-inputs", type=Path)
    parser.add_argument("--historical-source-commit")
    parsed = parser.parse_args(argv)
    if parsed.capture_source:
        require(parsed.root is not None and parsed.output is not None, "--capture-source requires --root and --output")
        require(parsed.work is None and parsed.product_report is None and parsed.historical_inputs is None
                and parsed.historical_source_commit is None, "invalid --capture-source arguments")
    elif parsed.check_work:
        require(parsed.work is not None, "--check-work requires --work")
        require(all(value is None for value in (
            parsed.root, parsed.output, parsed.product_report, parsed.historical_inputs,
            parsed.historical_source_commit,
        )), "invalid --check-work arguments")
    elif parsed.collect_report:
        require(all(value is not None for value in (
            parsed.root, parsed.work, parsed.product_report, parsed.historical_inputs, parsed.historical_source_commit,
        )), "--collect-report requires --root, --work, --product-report, --historical-inputs, and --historical-source-commit")
        require(parsed.output is None, "--collect-report does not take --output")
    else:
        require(all(value is None for value in (
            parsed.root, parsed.work, parsed.output, parsed.product_report, parsed.historical_inputs,
            parsed.historical_source_commit,
        )), "--validate-report takes only REPORT")
    return parsed


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parse_args(sys.argv[1:] if argv is None else argv)
        if args.capture_source:
            capture_source(args.root, args.output)
        elif args.check_work:
            evaluate_alias_contract(args.work.resolve(strict=True))
            evaluate_final_extraction(args.work.resolve(strict=True))
        elif args.collect_report:
            report = collect_report(
                args.work, args.root, args.product_report, args.historical_inputs, args.historical_source_commit
            )
            print(report)
        else:
            validate_report(args.validate_report)
    except (OSError, ReceiptError) as error:
        raise SystemExit(f"owned pthread timed feature receipt: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
