#!/usr/bin/env python3
"""Collect and replay a retained native x86-64 locale/time alias receipt.

``run_locale_alias_contract.sh`` owns the normal installed-header consumer.  It
proves the complete existing 98-name selected contract: 43 ordinary
public/internal pairs, four time pairs, the file-local ``tzset`` distinction,
the reverse ``freelocale`` spelling, and two direct entries.  This reader does
not promote that component.  It records the sources, fresh installed products,
pinned musl bytes, every runner command and all raw streams so a host can later
replay the finite relation without starting a compiler, linker, target process,
or container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import re
import tempfile
import zlib
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
SOURCE_MOUNT = "/workspace"
SCHEMA = "crabc.x86_64-locale-alias-contract-receipt/v2"
COMMAND_SCHEMA = "crabc.x86_64-locale-alias-contract-command/v2"
IMAGE_MANIFEST_PATH = "compat/x86_64/locale-alias-contract-image-inputs.json"
PINNED_IMAGE = "crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
COMMAND_PATH = "/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
COMMAND_ENVIRONMENT = {"LC_ALL": "C", "PATH": COMMAND_PATH}
# The product builders re-open the mounted Git checkout after the collector
# intentionally uses ``env -i``. Retain this one literal safe-directory entry
# inside every collector command; outer Docker environment cannot cross that
# closed process boundary, and a wildcard would weaken source admission.
COLLECTOR_GIT_SAFE_DIRECTORY = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": SOURCE_MOUNT,
}
RUNNER_TIMEOUT_SECONDS = 20
COLLECTOR_TIMEOUT_SECONDS = 1200
COMMAND_LAUNCHER_PREFIX = ("/usr/bin/env", "-i")
RUNNER_LAUNCHER = [*COMMAND_LAUNCHER_PREFIX, "LC_ALL=C", f"PATH={COMMAND_PATH}", "/usr/bin/timeout", str(RUNNER_TIMEOUT_SECONDS)]
IMAGE_INPUTS = (
    "/bin/bash", "/bin/chmod", "/bin/cp", "/bin/grep", "/bin/ln", "/bin/mkdir", "/bin/mktemp", "/bin/sh", "/bin/uname",
    "/opt/cargo/bin/rustup", "/opt/musl-1.2.6/lib/libc.a", "/opt/musl-1.2.6/lib/libc.so", "/opt/musl-1.2.6/lib/musl-gcc.specs",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/bin/rustc",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-ar",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-nm",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-objdump",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld",
    "/usr/bin/as", "/usr/bin/cmp", "/usr/bin/env", "/usr/bin/gcc", "/usr/bin/git", "/usr/bin/ld", "/usr/bin/python3", "/usr/bin/readelf",
    "/usr/bin/realpath", "/usr/bin/sha256sum", "/usr/bin/timeout",
    "/usr/libexec/gcc/x86_64-alpine-linux-musl/15.2.0/cc1", "/usr/libexec/gcc/x86_64-alpine-linux-musl/15.2.0/collect2",
    "/usr/libexec/gcc/x86_64-alpine-linux-musl/15.2.0/liblto_plugin.so", "/usr/local/bin/crabc-x86_64-musl-gcc", "/usr/sbin/chroot",
)

# Every retained regular file carries its observed permissions.  Source modes
# are additionally authenticated by the complete clean Git tree; immutable
# image inputs come from the checked-in manifest; product trees include every
# directory, regular file, and symlink; and consumer artifacts/raw streams are
# retained at their observed modes under the runner's ordinary ``umask 022``.
MODE_POLICY = {
    "source": "complete clean Git tree bytes and modes; replay admits current HEAD and every tracked byte/mode",
    "tools": "checked-in pinned-image manifest bytes, modes, invocation paths, and product LLVM producer-tool identities",
    "products": "static primary/reproduction/extracted preparation and dynamic product trees are retained with mode",
    "consumers": "normal installed-header runner uses umask 022 and retains every artifact and raw stream mode",
}

def _collector_environment(output_relative: str) -> dict[str, str]:
    return {**COMMAND_ENVIRONMENT, "TMPDIR": _mount(f"{output_relative}/tmp"), "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
            **COLLECTOR_GIT_SAFE_DIRECTORY}


def _collector_launcher(output_relative: str) -> list[str]:
    environment = _collector_environment(output_relative)
    return [*COMMAND_LAUNCHER_PREFIX, *(f"{key}={value}" for key, value in environment.items()),
            "/usr/bin/timeout", str(COLLECTOR_TIMEOUT_SECONDS)]
MUSL_RELEASE = "musl-1.2.6"
MUSL_REVISION = "9fa28ece75d8a2191de7c5bb53bed224c5947417"
MUSL_SOURCE_SHA256 = "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
ORACLE_ROOT = Path("/opt/musl-1.2.6")
ORACLE_COMPILER = "/usr/local/bin/crabc-x86_64-musl-gcc"

CONTRACT_PATH = "compat/x86_64/locale_alias_contract.json"
PROBE_PATH = "compat/x86_64/locale_alias_contract_probe.c"
SYMBOL_READER_PATH = "compat/x86_64/locale_alias_contract_symbols.py"
RUNNER_PATH = "compat/x86_64/run_locale_alias_contract.sh"
DOCUMENT_PATH = "compat/x86_64/locale-alias-contract.md"
STATIC_BUILDER_PATH = "scripts/build_x86_64_owned_sysroot.py"
DYNAMIC_BUILDER_PATH = "scripts/build_x86_64_owned_dynamic_sysroot.py"
PRODUCT_READER_PATH = "compat/x86_64/owned_posix_product_evidence.py"
STATIC_PREPARATION_OWNER_PATH = "compat/x86_64/owned_posix_static_products.py"
STATIC_PACKAGE_OWNER_PATH = "compat/x86_64/owned_static_sysroot_package.py"
STATIC_PREPARATION_DIRECTORY = "static-preparation"
STATIC_PRODUCT_DIRECTORY = f"{STATIC_PREPARATION_DIRECTORY}/products/primary"
DYNAMIC_PRODUCT_DIRECTORY = "products/dynamic"
PRODUCER_TOOL_PATHS = {
    name: "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/"
          "lib/rustlib/x86_64-unknown-linux-musl/bin/" + name
    for name in ("llvm-ar", "llvm-nm", "llvm-objdump")
}
DYNAMIC_LINKER_PATH = "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/" \
                      "lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
IMPLEMENTATION_SOURCES = (
    "libc/src/c_abi/x86_64/locale_narrow.rs",
    "libc/src/c_abi/x86_64/locale_objects.rs",
    "libc/src/c_abi/x86_64/gmtime_r.rs",
    "libc/src/c_abi/x86_64/owned_calendar.rs",
    "libc/src/c_abi/x86_64/owned_strftime.rs",
    "libc/src/c_abi/x86_64/owned_timezone.rs",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
)
SELECTED_SOURCES = (
    CONTRACT_PATH,
    PROBE_PATH,
    SYMBOL_READER_PATH,
    RUNNER_PATH,
    DOCUMENT_PATH,
    "compat/x86_64/tests/test_locale_alias_contract.py",
    "compat/x86_64/tests/test_locale_alias_contract_receipt.py",
    STATIC_BUILDER_PATH,
    DYNAMIC_BUILDER_PATH,
    PRODUCT_READER_PATH,
    IMAGE_MANIFEST_PATH,
    STATIC_PREPARATION_OWNER_PATH,
    STATIC_PACKAGE_OWNER_PATH,
    "compat/x86_64/owned_syscall_alias_authority.py",
    "compat/x86_64/owned_utmpx_receipt.py",
    "compat/x86_64/owned_dynamic_receipt.py",
    "compat/x86_64/crabc_cc_owned_dynamic.py",
    "compat/x86_64/owned_dynamic_qualification.py",
    "compat/x86_64/locale_alias_contract_receipt.py",
    *IMPLEMENTATION_SOURCES,
    "compat/upstreams.toml",
    "docker/Dockerfile.x86_64",
    "docker/x86_64-musl-oracle-gcc",
)

# The runner produces one stream set for each external command.  Snapshots are
# separate input seals, not command records; the collector runner invocation is
# retained separately in ``collector_commands``.
RUNNER_DIRECTORY = "tmp/runner"

RUNNER_STEMS = (
    "compile",
    "oracle-static-link",
    "candidate-static-link",
    "candidate-static-pie-link",
    "oracle-dynamic-pie-link",
    "candidate-dynamic-pie-link",
    "oracle-dynamic-non-pie-link",
    "candidate-dynamic-non-pie-link",
    "oracle-static-header",
    "candidate-static-header",
    "candidate-static-pie-header",
    "oracle-dynamic-pie-header",
    "oracle-dynamic-non-pie-header",
    "candidate-dynamic-pie-header",
    "candidate-dynamic-non-pie-header",
    "oracle-static-run",
    "candidate-static-run",
    "candidate-static-pie-run",
    "oracle-dynamic-pie-kernel",
    "candidate-dynamic-pie-kernel",
    "oracle-dynamic-pie-direct",
    "candidate-dynamic-pie-direct",
    "oracle-dynamic-non-pie-kernel",
    "candidate-dynamic-non-pie-kernel",
    "oracle-dynamic-non-pie-direct",
    "candidate-dynamic-non-pie-direct",
    "oracle-static-symbols",
    "oracle-dynamic-symbols",
    "oracle-shared-symbols",
    "candidate-static-symbols",
    "candidate-dynamic-symbols",
    "candidate-shared-symbols",
    "executable-dynamic-pie-symbols",
    "executable-dynamic-non-pie-symbols",
    "alias-symbol-observation",
)

# The normal dynamic driver writes a sealed receipt beside each candidate
# executable it links. They are not extra commands or probes: the two fixed
# receipts describe the already-recorded PIE and non-PIE consumer links. Keep
# their names, modes, bytes, and source-owned link claims finite here instead
# of accepting every ``*.crabc-link.json`` file the driver might create.
DYNAMIC_EXECUTABLE_LINK_SIDECARS = (
    ("candidate-dynamic-pie", "candidate-dynamic-pie.crabc-link.json", "pie"),
    ("candidate-dynamic-non-pie", "candidate-dynamic-non-pie.crabc-link.json", "non-pie"),
)

RUNNER_ARTIFACTS = (
    "probe.o", "oracle-static", "candidate-static", "candidate-static-pie",
    "oracle-dynamic-pie", "oracle-dynamic-non-pie",
    "candidate-dynamic-pie", "candidate-dynamic-non-pie",
    *(sidecar for _executable, sidecar, _linkage in DYNAMIC_EXECUTABLE_LINK_SIDECARS),
)

RUNNER_GENERATED_ENTRIES = (
    *RUNNER_ARTIFACTS,
    "oracle-dynamic-root", "candidate-dynamic-root",
)

STATUS = {
    "component": "measured-current-source",
    "family_completion": False,
    "runtime_qualification": False,
    "selection_closure": False,
    "public_support": False,
}
NONCLAIMS = (
    "This receipt retains only the existing selected locale/time alias contract.",
    "It does not add wcsftime_l, a general locale catalog, legacy encodings, or timezone-data qualification.",
    "The receipt does not infer selected static feature placement from symbol presence.",
    "It is not native ABI selection, runtime qualification, family completion, or public x86 support.",
)


class LocaleAliasReceiptError(ValueError):
    """A retained locale/time alias receipt differs from its finite contract."""


def _fail(message: str) -> None:
    raise LocaleAliasReceiptError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
    except OSError as error:
        _fail(f"cannot read retained file {path}: {error}")
    return digest.hexdigest()


def _strict_json(path: Path, label: str) -> Any:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise LocaleAliasReceiptError(f"{label} is not strict JSON") from error
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("retained JSON repeats an object key")
        result[key] = value
    return result


def _exact_mapping(value: object, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail(f"{label} fields changed")
    return value


def _relative_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        _fail(f"{label} path is absent")
    candidate = Path(value)
    if candidate.is_absolute() or any(part in {".", ".."} for part in candidate.parts):
        _fail(f"{label} path escapes receipt root")
    path = root / candidate
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LocaleAliasReceiptError(f"{label} is absent") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        _fail(f"{label} is not a regular retained file")
    return path


def _relative_directory(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        _fail(f"{label} directory is absent")
    candidate = Path(value)
    if candidate.is_absolute() or any(part in {".", ".."} for part in candidate.parts):
        _fail(f"{label} directory escapes receipt root")
    path = root / candidate
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LocaleAliasReceiptError(f"{label} directory is absent") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        _fail(f"{label} directory is not physical")
    return path


def _file_record(root: Path, value: object, label: str) -> dict[str, object]:
    record = _exact_mapping(value, {"path", "bytes", "sha256", "mode"}, label)
    path = _relative_file(root, record["path"], label)
    if type(record["bytes"]) is not int or record["bytes"] < 0:
        _fail(f"{label} byte count is invalid")
    if not isinstance(record["sha256"], str) or len(record["sha256"]) != 64:
        _fail(f"{label} hash is invalid")
    try:
        actual_bytes = path.stat().st_size
    except OSError as error:
        raise LocaleAliasReceiptError(f"{label} cannot be statted") from error
    if actual_bytes != record["bytes"]:
        _fail(f"{label} byte count changed")
    if _sha256(path) != record["sha256"]:
        _fail(f"{label} bytes changed")
    if type(record["mode"]) is not int or not 0 <= record["mode"] <= 0o777:
        _fail(f"{label} mode is invalid")
    if stat.S_IMODE(path.stat().st_mode) != record["mode"]:
        _fail(f"{label} mode changed")
    return {"path": record["path"], "bytes": record["bytes"], "sha256": record["sha256"], "mode": record["mode"]}


def _identity(root: Path, path: Path) -> dict[str, object]:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise LocaleAliasReceiptError(f"retained path is outside receipt root: {path}") from error
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        _fail(f"retained path is not a physical regular file: {relative}")
    return {"path": relative, "bytes": metadata.st_size, "sha256": _sha256(path), "mode": stat.S_IMODE(metadata.st_mode)}


def _copy_regular(source: Path, destination: Path) -> None:
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
        _fail(f"collection input is not a physical regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(metadata.st_mode))


def _mount(relative: str) -> str:
    return f"{SOURCE_MOUNT}/{relative}"


def _output_relative(root: Path, output: Path) -> str:
    try:
        relative = output.relative_to(root).as_posix()
    except ValueError as error:
        raise LocaleAliasReceiptError("receipt output must be below the checkout") from error
    if not relative.startswith(".work/x86_64/"):
        _fail("receipt output must be below checkout .work/x86_64")
    return relative


def validate_command_record(
    root: Path,
    value: object,
    *,
    role: str,
    cwd: str,
    argv: Sequence[str],
    environment: Mapping[str, str],
    launcher: Sequence[str],
) -> dict[str, object]:
    """Validate one successful command and its immutable launch-context streams."""

    record = _exact_mapping(
        value,
        {"schema", "role", "cwd", "argv", "status", "environment", "stdin", "launcher", "stdout", "stderr", "status_stream", "cwd_stream", "environment_stream", "stdin_stream", "launcher_stream"},
        "retained command",
    )
    if record["schema"] != COMMAND_SCHEMA or record["role"] != role:
        _fail("retained command identity changed")
    if record["cwd"] != cwd:
        _fail("retained command cwd changed")
    if record["argv"] != list(argv):
        _fail("retained command argv changed")
    if record["status"] != 0:
        _fail("retained command status changed")
    if record["environment"] != dict(environment):
        _fail("retained command environment changed")
    if record["stdin"] != "/dev/null":
        _fail("retained command stdin changed")
    if record["launcher"] != list(launcher):
        _fail("retained command launcher changed")
    result = {name: _file_record(root, record[name], f"retained command {name}")
              for name in ("stdout", "stderr", "status_stream", "cwd_stream", "environment_stream", "stdin_stream", "launcher_stream")}
    status_path = _relative_file(root, result["status_stream"]["path"], "retained command status")
    if status_path.read_bytes() != b"0\n":
        _fail("retained command raw status stream changed")
    if _relative_file(root, result["cwd_stream"]["path"], "retained command cwd").read_bytes() != (cwd + "\n").encode():
        _fail("retained command cwd stream changed")
    if _strict_json(_relative_file(root, result["environment_stream"]["path"], "retained command environment"), "retained command environment") != dict(environment):
        _fail("retained command environment stream changed")
    if _relative_file(root, result["stdin_stream"]["path"], "retained command stdin").read_bytes() != b"/dev/null\n":
        _fail("retained command stdin stream changed")
    if _strict_json(_relative_file(root, result["launcher_stream"]["path"], "retained command launcher"), "retained command launcher") != record["launcher"]:
        _fail("retained command launcher stream changed")
    return {"role": role, "argv": list(argv), "cwd": cwd, "status": 0,
            "environment": dict(environment), "stdin": "/dev/null", "launcher": record["launcher"], **result}


def source_records(root: Path, paths: Iterable[str]) -> list[dict[str, object]]:
    """Record an ordered finite source roster relative to one physical root."""

    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in paths:
        if not isinstance(value, str) or not value or value in seen:
            _fail("source roster is not finite and unique")
        seen.add(value)
        path = _relative_file(root, value, "source")
        records.append({"path": value, "bytes": path.stat().st_size, "sha256": _sha256(path), "mode": stat.S_IMODE(path.stat().st_mode)})
    if not records:
        _fail("source roster is empty")
    return records


def validate_source_records(root: Path, records: object) -> list[dict[str, object]]:
    """Rehash every selected current source input without running a process."""

    if not isinstance(records, list) or not records:
        _fail("source records are absent")
    validated: list[dict[str, object]] = []
    seen: set[str] = set()
    for record in records:
        item = _file_record(root, record, "source")
        path = item["path"]
        if path in seen:
            _fail("source roster repeats a path")
        seen.add(path)
        validated.append(item)
    return validated


def _contract(root: Path) -> dict[str, Any]:
    value = _strict_json(root / CONTRACT_PATH, "locale alias contract")
    expected = {
        "schema", "oracle", "visible_aliases", "hidden_aliases", "file_local_aliases",
        "reverse_visible_aliases", "non_alias_locale_entries", "family_completion",
        "promotion_ready", "public_support",
    }
    record = _exact_mapping(value, expected, "locale alias contract")
    if record["schema"] != "crabc.x86_64-locale-alias-contract/v1":
        _fail("locale alias contract schema changed")
    if record["oracle"] != {"release": MUSL_RELEASE, "revision": MUSL_REVISION}:
        _fail("locale alias oracle changed")
    visible = record["visible_aliases"]
    hidden = record["hidden_aliases"]
    if not isinstance(visible, Mapping) or not isinstance(hidden, Mapping):
        _fail("locale alias pairs are malformed")
    if len(visible) != 43 or len(hidden) != 4 or set(visible) & set(hidden):
        _fail("locale alias pair roster changed")
    if any(not isinstance(name, str) or internal != "__" + name
           for aliases in (visible, hidden) for name, internal in aliases.items()):
        _fail("locale alias pair spelling changed")
    if record["file_local_aliases"] != {"tzset": "__tzset"}:
        _fail("locale file-local alias contract changed")
    if record["reverse_visible_aliases"] != {"freelocale": "__freelocale"}:
        _fail("locale reverse alias contract changed")
    if record["non_alias_locale_entries"] != ["wcscasecmp_l", "wcsncasecmp_l"]:
        _fail("locale direct entry roster changed")
    if (record["family_completion"], record["promotion_ready"], record["public_support"]) != (False, False, False):
        _fail("locale alias contract promotion state changed")
    return dict(record)


def validate_source_contract(root: Path) -> dict[str, object]:
    """Bind source-owned aliases without inventing static feature placement."""

    contract = _contract(root)
    texts = {path: (root / path).read_text(encoding="utf-8") for path in IMPLEMENTATION_SOURCES}
    combined = "\n".join(texts.values())
    for group in (contract["visible_aliases"], contract["hidden_aliases"]):
        assert isinstance(group, Mapping)
        for public, internal in group.items():
            if f'.weak {public}' not in combined or f'.set {public}, {internal}' not in combined:
                _fail(f"source weak alias declaration changed: {public}")
            if (f'#[export_name = "{internal}"]' not in combined
                    and '#[export_name = $internal]' not in combined
                    and f'{public}, "{internal}"' not in combined):
                _fail(f"source internal body export changed: {internal}")
    for public, internal in contract["hidden_aliases"].items():
        if f'".hidden {internal}"' not in combined:
            _fail(f"source hidden time alias declaration changed: {internal}")
    objects = texts["libc/src/c_abi/x86_64/locale_objects.rs"]
    timezone = texts["libc/src/c_abi/x86_64/owned_timezone.rs"]
    static_c_abi = texts["libc/src/c_abi/x86_64/static_c_abi.rs"]
    oracle_wrapper = (root / "docker/x86_64-musl-oracle-gcc").read_text(encoding="utf-8")
    if '".weak __freelocale", ".set __freelocale, freelocale"' not in objects:
        _fail("source reverse freelocale declaration changed")
    if '#[linkage = "weak"]\npub extern "C" fn tzset()' not in timezone:
        _fail("source public tzset declaration changed")
    if 'fn refresh_tzset()' not in timezone or 'export_name = "__tzset"' in timezone:
        _fail("source local tzset boundary changed")
    for source in IMPLEMENTATION_SOURCES[:-1]:
        filename = Path(source).name
        if f'#[path = "{filename}"]' not in static_c_abi:
            _fail(f"selected static source is not composed: {filename}")
    if not oracle_wrapper.startswith("#!/bin/sh\n") or 'exec /usr/bin/gcc -specs /opt/musl-1.2.6/lib/musl-gcc.specs "$@"' not in oracle_wrapper:
        _fail("pinned musl compiler wrapper changed")
    return {
        "visible_pairs": len(contract["visible_aliases"]),
        "hidden_pairs": len(contract["hidden_aliases"]),
        "file_local_alias": "tzset/__tzset (source-local oracle distinction)",
        "reverse_visible_alias": "freelocale/__freelocale",
        "direct_entries": list(contract["non_alias_locale_entries"]),
        "wcsftime_l_in_contract": False,
    }


def _runner_plan(output_relative: str) -> list[tuple[str, list[str]]]:
    """Reconstruct every runner ``capture`` argv in its fixed execution order."""

    work = _mount(f"{output_relative}/{RUNNER_DIRECTORY}")
    static = _mount(f"{output_relative}/{STATIC_PRODUCT_DIRECTORY}")
    dynamic = _mount(f"{output_relative}/{DYNAMIC_PRODUCT_DIRECTORY}")
    probe = _mount(PROBE_PATH)
    contract = _mount(CONTRACT_PATH)
    symbol_reader = _mount(SYMBOL_READER_PATH)
    plan: list[tuple[str, list[str]]] = []
    add = lambda label, argv: plan.append((label, argv))
    add("compile", [f"{dynamic}/bin/crabc-cc-dynamic", "--dynamic-pie", "-std=c11", "-D_GNU_SOURCE",
                    "-fno-builtin", "-fno-stack-protector", "-c", probe, "-o", f"{work}/probe.o"])
    add("oracle-static-link", [ORACLE_COMPILER, "-static", "-no-pie", f"{work}/probe.o", "-o", f"{work}/oracle-static"])
    add("candidate-static-link", [f"{static}/bin/crabc-cc", "-static", f"{work}/probe.o", "-o", f"{work}/candidate-static"])
    add("candidate-static-pie-link", [f"{static}/bin/crabc-cc", "-static-pie", f"{work}/probe.o", "-o", f"{work}/candidate-static-pie"])
    for mode, flags in (("pie", ["-rdynamic", "-fPIE", "-pie"]), ("non-pie", ["-rdynamic", "-no-pie"])):
        add(f"oracle-dynamic-{mode}-link", [ORACLE_COMPILER, *flags, f"{work}/probe.o", "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1", "-o", f"{work}/oracle-dynamic-{mode}"])
        add(f"candidate-dynamic-{mode}-link", [f"{dynamic}/bin/crabc-cc-dynamic", f"--dynamic-{mode}", "-rdynamic", f"{work}/probe.o", "-o", f"{work}/candidate-dynamic-{mode}"])
    for executable in ("oracle-static", "candidate-static", "candidate-static-pie", "oracle-dynamic-pie", "oracle-dynamic-non-pie", "candidate-dynamic-pie", "candidate-dynamic-non-pie"):
        add(f"{executable}-header", ["/usr/bin/readelf", "-h", f"{work}/{executable}"])
    add("oracle-static-run", ["/usr/bin/env", "-i", "TZ=UTC", f"{work}/oracle-static"])
    add("candidate-static-run", ["/usr/bin/env", "-i", "TZ=UTC", f"{work}/candidate-static"])
    add("candidate-static-pie-run", ["/usr/bin/env", "-i", "TZ=UTC", f"{work}/candidate-static-pie"])
    for mode in ("pie", "non-pie"):
        for entry in ("kernel", "direct"):
            oracle = ["/usr/sbin/chroot", f"{work}/oracle-dynamic-root"]
            candidate = ["/usr/sbin/chroot", f"{work}/candidate-dynamic-root"]
            if entry == "kernel":
                oracle.append(f"/consumer-{mode}")
                candidate.append(f"/consumer-{mode}")
            else:
                oracle.extend(["/lib/ld-musl-x86_64.so.1", f"/consumer-{mode}"])
                candidate.extend(["/lib/ld-crabc-x86_64.so.1", f"/consumer-{mode}"])
            add(f"oracle-dynamic-{mode}-{entry}", oracle)
            add(f"candidate-dynamic-{mode}-{entry}", candidate)
    add("oracle-static-symbols", ["/usr/bin/readelf", "-Ws", "/opt/musl-1.2.6/lib/libc.a"])
    add("oracle-dynamic-symbols", ["/usr/bin/readelf", "--dyn-syms", "-W", "/opt/musl-1.2.6/lib/libc.so"])
    add("oracle-shared-symbols", ["/usr/bin/readelf", "-Ws", "/opt/musl-1.2.6/lib/libc.so"])
    add("candidate-static-symbols", ["/usr/bin/readelf", "-Ws", f"{static}/usr/lib/libc.a"])
    add("candidate-dynamic-symbols", ["/usr/bin/readelf", "--dyn-syms", "-W", f"{dynamic}/usr/lib/libc.so"])
    add("candidate-shared-symbols", ["/usr/bin/readelf", "-Ws", f"{dynamic}/usr/lib/libc.so"])
    add("executable-dynamic-pie-symbols", ["/usr/bin/readelf", "--dyn-syms", "-W", f"{work}/candidate-dynamic-pie"])
    add("executable-dynamic-non-pie-symbols", ["/usr/bin/readelf", "--dyn-syms", "-W", f"{work}/candidate-dynamic-non-pie"])
    add("alias-symbol-observation", ["/usr/bin/python3", "-B", symbol_reader, contract,
                                     f"{work}/oracle-static-symbols.stdout", f"{work}/oracle-dynamic-symbols.stdout", f"{work}/oracle-shared-symbols.stdout",
                                     f"{work}/candidate-static-symbols.stdout", f"{work}/candidate-dynamic-symbols.stdout", f"{work}/candidate-shared-symbols.stdout",
                                     f"{work}/executable-dynamic-pie-symbols.stdout", f"{work}/executable-dynamic-non-pie-symbols.stdout", f"{work}/alias-observation.json"])
    if tuple(label for label, _argv in plan) != RUNNER_STEMS:
        raise RuntimeError("locale alias runner plan drifted from its fixed stem roster")
    return plan


def _runner_records(root: Path, output_relative: str, records: object) -> list[dict[str, object]]:
    if not isinstance(records, list) or len(records) != len(RUNNER_STEMS):
        _fail("runner command roster changed")
    actual = _raw_runner_records(root, output_relative)
    if records != actual:
        _fail("runner command records do not name the retained raw streams")
    return actual


def _raw_runner_records(root: Path, output_relative: str) -> list[dict[str, object]]:
    raw = _relative_directory(root, RUNNER_DIRECTORY, "runner raw")
    expected = {f"{stem}.{suffix}" for stem in RUNNER_STEMS
                for suffix in ("argv.json", "cwd", "environment.json", "stdin", "launcher.json", "stdout", "stderr", "status")}
    expected.update({"before.sha256", "after.sha256", "alias-observation.json"})
    generated = set(RUNNER_GENERATED_ENTRIES)
    actual = {path.name for path in raw.iterdir()}
    if actual != expected | generated:
        _fail("runner raw file roster changed")
    records: list[dict[str, object]] = []
    for stem in RUNNER_STEMS:
        argv_path = raw / f"{stem}.argv.json"
        argv = _strict_json(argv_path, f"runner argv {stem}")
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            _fail(f"runner argv is malformed: {stem}")
        cwd_path = raw / f"{stem}.cwd"
        if cwd_path.is_symlink() or not cwd_path.is_file():
            _fail(f"runner cwd is not a physical raw file: {stem}")
        try:
            cwd = cwd_path.read_text(encoding="utf-8")
        except OSError as error:
            raise LocaleAliasReceiptError(f"runner cwd is absent: {stem}") from error
        if cwd != SOURCE_MOUNT + "\n":
            _fail(f"runner cwd changed: {stem}")
        records.append({
            "schema": COMMAND_SCHEMA,
            "role": stem,
            "cwd": SOURCE_MOUNT,
            "argv": argv,
            "status": 0 if (raw / f"{stem}.status").read_bytes() == b"0\n" else -1,
            "environment": COMMAND_ENVIRONMENT,
            "stdin": "/dev/null",
            "launcher": RUNNER_LAUNCHER,
            "stdout": _identity(root, raw / f"{stem}.stdout"),
            "stderr": _identity(root, raw / f"{stem}.stderr"),
            "status_stream": _identity(root, raw / f"{stem}.status"),
            "cwd_stream": _identity(root, cwd_path),
            "environment_stream": _identity(root, raw / f"{stem}.environment.json"),
            "stdin_stream": _identity(root, raw / f"{stem}.stdin"),
            "launcher_stream": _identity(root, raw / f"{stem}.launcher.json"),
        })
    for record, (role, argv) in zip(records, _runner_plan(output_relative)):
        validate_command_record(root, record, role=role, cwd=SOURCE_MOUNT, argv=argv, environment=COMMAND_ENVIRONMENT, launcher=RUNNER_LAUNCHER)
    return records


def _snapshot(root: Path, name: str) -> dict[str, object]:
    path = _relative_file(root, f"{RUNNER_DIRECTORY}/{name}.sha256", f"runner {name} snapshot")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise LocaleAliasReceiptError(f"runner {name} snapshot is invalid") from error
    expected_names = (
        PROBE_PATH,
        CONTRACT_PATH,
        SYMBOL_READER_PATH,
        f"{STATIC_PRODUCT_DIRECTORY}/usr/lib/libc.a",
        f"{DYNAMIC_PRODUCT_DIRECTORY}/usr/lib/libc.so",
    )
    if len(lines) != len(expected_names):
        _fail(f"runner {name} snapshot roster changed")
    records: list[dict[str, str]] = []
    for line, expected in zip(lines, expected_names):
        try:
            digest, filename = line.split("  ", 1)
        except ValueError as error:
            raise LocaleAliasReceiptError(f"runner {name} snapshot row is malformed") from error
        if len(digest) != 64 or filename != _mount(expected):
            _fail(f"runner {name} snapshot path changed")
        records.append({"path": expected, "sha256": digest})
    return {"stream": _identity(root, path), "records": records}


def _validate_snapshot(root: Path, value: object, name: str) -> dict[str, object]:
    record = _exact_mapping(value, {"stream", "records"}, f"runner {name} snapshot")
    current = _snapshot(root, name)
    if record != current:
        _fail(f"runner {name} snapshot bytes changed")
    return current


def _validate_runtime_and_headers(root: Path) -> dict[str, object]:
    raw = root / RUNNER_DIRECTORY
    expected_types = {
        "oracle-static": "EXEC", "candidate-static": "EXEC", "candidate-static-pie": "DYN",
        "oracle-dynamic-pie": "DYN", "oracle-dynamic-non-pie": "EXEC",
        "candidate-dynamic-pie": "DYN", "candidate-dynamic-non-pie": "EXEC",
    }
    for executable, elf_type in expected_types.items():
        text = (raw / f"{executable}-header.stdout").read_text(encoding="utf-8")
        if not any(line.split()[:2] == ["Type:", elf_type] for line in text.splitlines()):
            _fail(f"retained ELF header type changed: {executable}")
    for candidate in ("candidate-static-run", "candidate-static-pie-run"):
        for suffix in ("stdout", "stderr", "status"):
            if (raw / f"oracle-static-run.{suffix}").read_bytes() != (raw / f"{candidate}.{suffix}").read_bytes():
                _fail(f"retained static runtime transcript changed: {candidate}")
    for mode in ("pie", "non-pie"):
        for entry in ("kernel", "direct"):
            for suffix in ("stdout", "stderr", "status"):
                oracle = raw / f"oracle-dynamic-{mode}-{entry}.{suffix}"
                candidate = raw / f"candidate-dynamic-{mode}-{entry}.{suffix}"
                if oracle.read_bytes() != candidate.read_bytes():
                    _fail(f"retained dynamic runtime transcript changed: {mode}/{entry}")
    return {"headers": expected_types, "static_rows": 2, "dynamic_rows": 4}


def _artifacts(root: Path) -> dict[str, dict[str, object]]:
    raw = _relative_directory(root, RUNNER_DIRECTORY, "runner raw")
    return {name: _identity(root, raw / name) for name in RUNNER_ARTIFACTS}


def _validate_artifacts(root: Path, value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, Mapping):
        _fail("compiled artifact identity is malformed")
    actual = _artifacts(root)
    if value != actual:
        _fail("compiled object or linked executable bytes changed")
    return actual


def _validate_dynamic_executable_link_sidecars(
    root: Path, image: Mapping[str, object],
) -> dict[str, dict[str, str]]:
    """Replay the two normal candidate executable link receipts without tools."""

    files = image.get("files")
    if not isinstance(files, Mapping):
        _fail("retained image linker authority is absent")
    image_entry = files.get(DYNAMIC_LINKER_PATH)
    if not isinstance(image_entry, Mapping):
        _fail("retained image linker authority is absent")
    image_identity = _exact_mapping(
        image_entry.get("image"), {"path", "sha256", "size", "mode"}, "retained dynamic linker identity",
    )
    if image_identity["path"] != DYNAMIC_LINKER_PATH:
        _fail("retained dynamic linker path changed")
    linker = {name: image_identity[name] for name in ("path", "sha256")}
    raw = _relative_directory(root, RUNNER_DIRECTORY, "runner raw")
    dynamic = _relative_directory(root, DYNAMIC_PRODUCT_DIRECTORY, "retained dynamic product")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_posix_product_evidence as product_evidence

    observed: dict[str, dict[str, str]] = {}
    for executable, sidecar, linkage in DYNAMIC_EXECUTABLE_LINK_SIDECARS:
        try:
            result = product_evidence.validate_retained_link(
                root, SOURCE_MOUNT, dynamic, raw / "probe.o", raw / executable, raw / sidecar, linkage,
                linker, export_dynamic=True,
            )
        except (product_evidence.ProductEvidenceError, OSError, ValueError) as error:
            raise LocaleAliasReceiptError(f"retained {executable} link receipt differs: {error}") from error
        expected = {
            "linkage", "product", "product_format", "product_manifest_sha256", "workload_sha256",
            "executable_sha256", "receipt_sha256",
        }
        if not isinstance(result, Mapping) or set(result) != expected or not all(isinstance(value, str) for value in result.values()):
            _fail(f"retained {executable} link validation changed")
        observed[executable] = dict(result)
    return observed


def _validate_symbol_observation(root: Path) -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import locale_alias_contract_symbols as symbols

    raw = root / RUNNER_DIRECTORY
    retained_contract = root / "inputs/source" / CONTRACT_PATH
    observation = symbols.validate_observation(
        retained_contract,
        raw / "oracle-static-symbols.stdout", raw / "oracle-dynamic-symbols.stdout", raw / "oracle-shared-symbols.stdout",
        raw / "candidate-static-symbols.stdout", raw / "candidate-dynamic-symbols.stdout", raw / "candidate-shared-symbols.stdout",
        raw / "executable-dynamic-pie-symbols.stdout", raw / "executable-dynamic-non-pie-symbols.stdout",
    )
    received = _strict_json(raw / "alias-observation.json", "retained alias observation")
    if received != observation:
        _fail("retained alias observation differs from reconstructed full roster")
    return observation


def _tree_records(root: Path, directory: str) -> list[dict[str, object]]:
    path = _relative_directory(root, directory, f"{directory} product")
    records: list[dict[str, object]] = []
    for candidate in sorted(path.rglob("*")):
        metadata = candidate.lstat()
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink():
            target = os.readlink(candidate)
            records.append({"path": relative, "kind": "symlink", "target": target,
                            "mode": stat.S_IMODE(metadata.st_mode)})
        elif stat.S_ISREG(metadata.st_mode):
            identity = _identity(root, candidate)
            records.append({"path": identity["path"], "kind": "file", "bytes": identity["bytes"],
                            "sha256": identity["sha256"], "mode": identity["mode"]})
        elif stat.S_ISDIR(metadata.st_mode):
            records.append({"path": relative, "kind": "directory", "mode": stat.S_IMODE(metadata.st_mode)})
        else:
            _fail(f"product has unsupported filesystem entry: {candidate}")
    if not records:
        _fail(f"{directory} product is empty")
    return records


def _copy_physical_tree(source: Path, destination: Path, label: str) -> None:
    """Copy a retained static-preparation tree without accepting links or devices."""

    metadata = source.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or source.is_symlink() or destination.exists():
        _fail(f"{label} tree is unsafe")
    destination.mkdir(parents=True, mode=stat.S_IMODE(metadata.st_mode))
    for candidate in sorted(source.rglob("*")):
        relative = candidate.relative_to(source)
        copied = destination / relative
        mode = candidate.lstat().st_mode
        if candidate.is_symlink():
            _fail(f"{label} tree contains a symlink")
        if stat.S_ISDIR(mode):
            copied.mkdir(mode=stat.S_IMODE(mode))
            os.chmod(copied, stat.S_IMODE(mode))
        elif stat.S_ISREG(mode):
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, copied)
            os.chmod(copied, stat.S_IMODE(mode))
        else:
            _fail(f"{label} tree has an unsupported entry")


def _materialize_authoritative_source(destination: Path, files: Mapping[str, tuple[int, bytes, bool]]) -> None:
    """Materialize the retained complete Git tree for the static owner only."""

    if destination.exists():
        _fail("static preparation source materialization already exists")
    destination.mkdir()
    for relative, (mode, data, symlink) in sorted(files.items()):
        candidate = Path(relative)
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            _fail("retained complete Git source path is unsafe")
        target = destination / candidate
        target.parent.mkdir(parents=True, exist_ok=True)
        if symlink:
            target.symlink_to(os.fsdecode(data))
        else:
            target.write_bytes(data)
            os.chmod(target, mode)


def _validate_static_preparation(
    checkout_root: Path,
    receipt_root: Path,
    source_state: Mapping[str, object],
    value: object,
) -> dict[str, object]:
    """Replay the established static preparation from the receipt's Git tree.

    Static product source provenance belongs to ``owned_posix_static_products``.
    The locale receipt retains that full primary/reproduction/extracted
    transaction and supplies its already-authenticated complete Git identity to
    the owner.  Its own before/after fields remain collection context only.
    """

    record = _exact_mapping(value, {"directory", "tree", "record"}, "retained static preparation")
    if record["directory"] != STATIC_PREPARATION_DIRECTORY:
        _fail("static preparation directory changed")
    preparation_root = _relative_directory(receipt_root, STATIC_PREPARATION_DIRECTORY, "retained static preparation")
    tree = _tree_records(receipt_root, STATIC_PREPARATION_DIRECTORY)
    if record["tree"] != tree:
        _fail("retained static preparation tree changed")
    preparation_record = _file_record(receipt_root, record["record"], "retained static preparation receipt")
    if preparation_record != _identity(receipt_root, preparation_root / "preparation.json"):
        _fail("retained static preparation receipt path changed")
    preparation = _strict_json(preparation_root / "preparation.json", "retained static preparation")
    if not isinstance(preparation, Mapping):
        _fail("retained static preparation is malformed")
    try:
        output_relative = receipt_root.relative_to(checkout_root).as_posix()
    except ValueError as error:
        raise LocaleAliasReceiptError("retained static preparation escaped the checkout") from error
    if preparation.get("work") != f"{output_relative}/{STATIC_PREPARATION_DIRECTORY}":
        _fail("retained static preparation work path changed")

    revision = source_state.get("revision")
    digest = source_state.get("content_sha256")
    if not isinstance(revision, str) or not isinstance(digest, str):
        _fail("static preparation source identity is malformed")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_posix_static_products as static_products
    import owned_syscall_alias_authority as authority

    try:
        derived, files = authority.source_tree(receipt_root, revision)
    except authority.AuthorityError as error:
        raise LocaleAliasReceiptError("retained static preparation source authority is invalid") from error
    expected_source = {"revision": revision, "content_sha256": digest}
    if derived != expected_source:
        _fail("retained static preparation source identity changed")
    scratch = checkout_root / ".work/x86_64/locale-alias-contract-replay"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".static-preparation.", dir=scratch) as temporary:
        materialized = Path(temporary) / "source"
        _materialize_authoritative_source(materialized, files)
        replay_preparation = materialized / str(preparation["work"])
        _copy_physical_tree(preparation_root, replay_preparation, "retained static preparation")
        original_source_identity = static_products.source_identity

        def sealed_source_identity(candidate: Path) -> dict[str, object]:
            if candidate != materialized:
                _fail("static preparation owner escaped the sealed source root")
            return dict(expected_source)

        try:
            static_products.source_identity = sealed_source_identity
            observed = static_products.validate_receipt(materialized, replay_preparation / "preparation.json")
        except (static_products.PreparationError, static_products.package.PackageError, OSError, ValueError) as error:
            raise LocaleAliasReceiptError(f"static preparation differs: {error}") from error
        finally:
            static_products.source_identity = original_source_identity
    if not isinstance(observed, Mapping):
        _fail("static preparation owner produced no record")
    primary = observed.get("products", {}).get("primary")
    if not isinstance(primary, Mapping) or not isinstance(primary.get("tree"), Mapping):
        _fail("static preparation has no primary product tree")
    product = receipt_root / STATIC_PRODUCT_DIRECTORY
    try:
        if primary["tree"] != static_products.tree_identity(product):
            _fail("static preparation primary differs from retained static product")
    except (static_products.PreparationError, static_products.package.PackageError, OSError, ValueError) as error:
        raise LocaleAliasReceiptError(f"static preparation primary differs: {error}") from error
    return {"directory": STATIC_PREPARATION_DIRECTORY, "tree": tree, "record": preparation_record}


def _validate_producer_tools(
    root: Path,
    product: Path,
    name: str,
    image: Mapping[str, object],
) -> dict[str, object]:
    """Bind the three target LLVM tools recorded by both product producers."""

    if name == "static":
        metadata = product / "share/crabc/manifest.json"
        value = _strict_json(metadata, "static product manifest")
        if not isinstance(value, Mapping):
            _fail("static product manifest is malformed")
        tools = value.get("producer_tools")
    else:
        metadata = product / "share/crabc/producer-tools.json"
        tools = _strict_json(metadata, "dynamic producer tools")
    if not isinstance(tools, Mapping):
        _fail(f"{name} product producer tools are absent")
    expected_fields = {"schema", "target", "toolchain", "selection", "rustup", "rustc", "llvm_target_tools"}
    if set(tools) != expected_fields or tools.get("schema") != 1 or tools.get("target") != "x86_64-unknown-linux-musl":
        _fail(f"{name} product producer tool record changed")
    llvm = tools.get("llvm_target_tools")
    if not isinstance(llvm, Mapping) or set(llvm) != set(PRODUCER_TOOL_PATHS):
        _fail(f"{name} product LLVM tool roster changed")
    files = image.get("files")
    if not isinstance(files, Mapping):
        _fail("retained image tool records are absent")
    normalized: dict[str, object] = {}
    for tool, invocation in PRODUCER_TOOL_PATHS.items():
        received = _exact_mapping(llvm[tool], {"path", "resolved_path", "sha256"}, f"{name} {tool} producer tool")
        image_record = files.get(invocation)
        if not isinstance(image_record, Mapping) or not isinstance(image_record.get("image"), Mapping):
            _fail(f"{name} {tool} image authority is absent")
        trusted = image_record["image"]
        if (received["path"], received["resolved_path"], received["sha256"]) != (
            invocation, trusted.get("path"), trusted.get("sha256"),
        ):
            _fail(f"{name} {tool} producer tool differs from pinned image")
        normalized[tool] = dict(received)
    return {"metadata": _identity(root, metadata), "llvm_target_tools": normalized}


def _validate_products(
    checkout_root: Path,
    root: Path,
    value: object,
    source_state: Mapping[str, object],
    image: Mapping[str, object],
) -> dict[str, object]:
    expected = {"static", "dynamic"}
    records = _exact_mapping(value, expected, "retained products")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_posix_product_evidence as products

    static_item = _exact_mapping(records["static"], {"tree", "manifest", "preparation"}, "static retained product")
    preparation = _validate_static_preparation(checkout_root, root, source_state, static_item["preparation"])
    static_tree = _tree_records(root, STATIC_PRODUCT_DIRECTORY)
    if static_item["tree"] != static_tree:
        _fail("static retained product tree changed")
    static_product = root / STATIC_PRODUCT_DIRECTORY
    static_manifest_path, _details = products._validate_static_product(static_product)
    static_manifest = _identity(root, static_manifest_path)
    if static_item["manifest"] != static_manifest:
        _fail("static retained product manifest changed")

    dynamic_item = _exact_mapping(records["dynamic"], {"tree", "manifest", "source_before", "source_after", "state"}, "dynamic retained product")
    if dynamic_item["source_before"] != source_state or dynamic_item["source_after"] != source_state:
        _fail("dynamic product source transaction changed")
    dynamic_tree = _tree_records(root, DYNAMIC_PRODUCT_DIRECTORY)
    if dynamic_item["tree"] != dynamic_tree:
        _fail("dynamic retained product tree changed")
    dynamic_product = root / DYNAMIC_PRODUCT_DIRECTORY
    dynamic_manifest_path, _details = products._validate_dynamic_product(dynamic_product)
    dynamic_manifest = _identity(root, dynamic_manifest_path)
    if dynamic_item["manifest"] != dynamic_manifest:
        _fail("dynamic retained product manifest changed")
    state_path = dynamic_product / "share/crabc/dynamic-product-state.json"
    dynamic_state = _identity(root, state_path)
    if dynamic_item["state"] != dynamic_state:
        _fail("dynamic product state changed")
    state_value = _strict_json(state_path, "dynamic product state")
    if not isinstance(state_value, Mapping) or state_value.get("source_sha256") != source_state["content_sha256"]:
        _fail("dynamic product source identity differs from receipt source")
    # The tool facts are derived from product metadata protected by the trees
    # above and the immutable image records.  They are checked here rather than
    # copied as a self-attested second product relation.
    _validate_producer_tools(root, static_product, "static", image)
    _validate_producer_tools(root, dynamic_product, "dynamic", image)
    return {
        "static": {"tree": static_tree, "manifest": static_manifest, "preparation": preparation},
        "dynamic": {"tree": dynamic_tree, "manifest": dynamic_manifest, "source_before": source_state,
                    "source_after": source_state, "state": dynamic_state},
    }


def _hex(value: object, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(character not in "0123456789abcdef" for character in value):
        _fail(f"{label} is invalid")
    return value


def _trusted_image_manifest() -> dict[str, object]:
    """Read the finite checked-in image input authority without probing a host."""

    value = _strict_json(ROOT / IMAGE_MANIFEST_PATH, "trusted locale image input manifest")
    manifest = _exact_mapping(value, {"schema", "image", "path", "files"}, "trusted locale image input manifest")
    if manifest["schema"] != "crabc.x86_64-locale-alias-image-inputs/v1":
        _fail("trusted locale image manifest schema changed")
    if manifest["image"] != PINNED_IMAGE.removeprefix("crabc-core-evidence@") or manifest["path"] != COMMAND_PATH:
        _fail("trusted locale image identity changed")
    files = manifest["files"]
    if not isinstance(files, Mapping) or not files:
        _fail("trusted locale image input roster is empty")
    if set(files) != set(IMAGE_INPUTS) or len(IMAGE_INPUTS) != len(set(IMAGE_INPUTS)):
        _fail("trusted locale image manifest has an unexpected oracle or tool roster")
    for invocation, record in files.items():
        if not isinstance(invocation, str) or not invocation.startswith("/"):
            _fail("trusted locale image invocation changed")
        entry = _exact_mapping(record, {"path", "sha256", "size", "mode"}, "trusted locale image input")
        if not isinstance(entry["path"], str) or not entry["path"].startswith("/"):
            _fail("trusted locale image physical path changed")
        _hex(entry["sha256"], 64, "trusted locale image hash")
        if type(entry["size"]) is not int or entry["size"] < 0 or type(entry["mode"]) is not int or not 0 <= entry["mode"] <= 0o777:
            _fail("trusted locale image input identity changed")
    return dict(manifest)


def _copy_image_inputs(root: Path, receipt_root: Path) -> dict[str, object]:
    """Copy each manifest-selected physical image input before any producer runs."""

    manifest = _trusted_image_manifest()
    files = manifest["files"]
    assert isinstance(files, Mapping)
    records: dict[str, object] = {}
    for index, invocation in enumerate(sorted(files)):
        expected = files[invocation]
        assert isinstance(expected, Mapping)
        try:
            source = Path(invocation).resolve(strict=True)
        except OSError as error:
            raise LocaleAliasReceiptError(f"pinned locale image input is absent: {invocation}") from error
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or source.is_symlink() or str(source) != expected["path"]:
            _fail(f"pinned locale image input physical path changed: {invocation}")
        if (_sha256(source), metadata.st_size, stat.S_IMODE(metadata.st_mode)) != (expected["sha256"], expected["size"], expected["mode"]):
            _fail(f"pinned locale image input bytes or mode changed: {invocation}")
        destination = receipt_root / "inputs/image" / f"{index:02d}-{expected['sha256']}"
        _copy_regular(source, destination)
        records[invocation] = {"image": dict(expected), "retained": _identity(receipt_root, destination)}
    return {"id": PINNED_IMAGE,
            "manifest": _identity(receipt_root, receipt_root / "inputs/source" / IMAGE_MANIFEST_PATH),
            "files": records}


def _validate_image_inputs(root: Path, value: object) -> dict[str, object]:
    record = _exact_mapping(value, {"id", "manifest", "files"}, "retained locale image inputs")
    if record["id"] != PINNED_IMAGE:
        _fail("retained locale image identity changed")
    manifest_record = _file_record(root, record["manifest"], "retained locale image manifest")
    if manifest_record != _identity(root, root / "inputs/source" / IMAGE_MANIFEST_PATH):
        _fail("retained locale image manifest is not the copied selected source")
    retained_manifest = _strict_json(root / manifest_record["path"], "retained locale image manifest")
    trusted = _trusted_image_manifest()
    if retained_manifest != trusted:
        _fail("retained locale image manifest differs from trusted source")
    entries = record["files"]
    if not isinstance(entries, Mapping) or set(entries) != set(trusted["files"]):
        _fail("retained locale image file roster changed")
    actual: dict[str, object] = {}
    for invocation in sorted(entries):
        item = _exact_mapping(entries[invocation], {"image", "retained"}, "retained locale image input")
        expected = trusted["files"][invocation]
        if item["image"] != expected:
            _fail("retained locale image input no longer matches its manifest")
        retained = _file_record(root, item["retained"], "retained locale image input")
        if {key: retained[key] for key in ("sha256", "bytes", "mode")} != {"sha256": expected["sha256"], "bytes": expected["size"], "mode": expected["mode"]}:
            _fail("retained locale image input bytes or mode changed")
        actual[invocation] = {"image": expected, "retained": retained}
    return {"id": PINNED_IMAGE, "manifest": manifest_record, "files": actual}


def _live_source_state(root: Path) -> dict[str, object]:
    """Require exact clean HEAD/tree and hash every source byte/mode, including untracked."""

    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_posix_static_products as static_products

    try:
        state = static_products.source_identity(root)
        tree = subprocess.check_output(["/usr/bin/git", "rev-parse", str(state["revision"]) + "^{tree}"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        raise LocaleAliasReceiptError("locale receipt cannot read the clean Git source state") from error
    _hex(state.get("revision"), 40, "source revision")
    _hex(tree, 40, "source tree")
    _hex(state.get("content_sha256"), 64, "source content digest")
    return {"revision": state["revision"], "tree": tree, "content_sha256": state["content_sha256"], "clean": True}


def _retained_git_tree(root: Path, revision: str) -> str:
    """Read the commit's tree object directly from retained Git bytes."""

    path = _relative_file(root, f"source/git-objects/{revision}", "retained Git commit")
    try:
        raw = zlib.decompress(path.read_bytes())
        header, body = raw.split(b"\0", 1)
    except (OSError, ValueError, zlib.error) as error:
        raise LocaleAliasReceiptError("retained Git commit is malformed") from error
    if hashlib.sha1(raw).hexdigest() != revision or header != b"commit " + str(len(body)).encode():
        _fail("retained Git commit identity changed")
    first = body.split(b"\n", 1)[0]
    if not first.startswith(b"tree "):
        _fail("retained Git commit omits its tree")
    return _hex(first[5:].decode("ascii", "strict"), 40, "retained Git tree")


def _capture_source_phase(root: Path, receipt_root: Path, directory: str, state: Mapping[str, object] | None = None) -> dict[str, object]:
    """Copy selected source after authenticating the complete clean Git tree."""

    live = _live_source_state(root)
    if state is not None and live != state:
        _fail("source changed during locale alias collection")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_syscall_alias_authority as authority

    if state is None:
        authority.capture_git_objects(root, receipt_root, [live["revision"]])
    try:
        authenticated, files = authority.source_tree(receipt_root, live["revision"])
    except authority.AuthorityError as error:
        raise LocaleAliasReceiptError("retained Git source authority is invalid") from error
    if authenticated != {"revision": live["revision"], "content_sha256": live["content_sha256"]} or _retained_git_tree(receipt_root, live["revision"]) != live["tree"]:
        _fail("retained complete Git source authority differs from clean source state")
    source_root = receipt_root / directory
    for relative in SELECTED_SOURCES:
        expected = files.get(relative)
        if expected is None or expected[2] or expected[0] != stat.S_IMODE((root / relative).stat().st_mode) or expected[1] != (root / relative).read_bytes():
            _fail(f"selected source differs from authenticated Git tree: {relative}")
        _copy_regular(root / relative, source_root / relative)
    return {**live, "paths": source_records(source_root, SELECTED_SOURCES)}


def _validate_source_seal(root: Path, value: object, source_directory: str) -> dict[str, object]:
    record = _exact_mapping(value, {"revision", "tree", "content_sha256", "clean", "paths"}, "source seal")
    if record["clean"] is not True or not isinstance(record["paths"], list):
        _fail("source seal is not clean")
    revision = _hex(record["revision"], 40, "source revision")
    tree = _hex(record["tree"], 40, "source tree")
    digest = _hex(record["content_sha256"], 64, "source content digest")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_syscall_alias_authority as authority
    try:
        authenticated, files = authority.source_tree(root, revision)
    except authority.AuthorityError as error:
        raise LocaleAliasReceiptError("retained complete Git source authority is invalid") from error
    if authenticated != {"revision": revision, "content_sha256": digest} or _retained_git_tree(root, revision) != tree:
        _fail("retained complete Git source authority differs from source seal")
    _validate_current_tracked_source(revision, digest, files)
    retained_root = _relative_directory(root, source_directory, "retained source")
    retained = source_records(retained_root, SELECTED_SOURCES)
    if record["paths"] != retained:
        _fail("retained source bytes changed")
    for source in retained:
        path = source["path"]
        expected = files.get(path)
        if expected is None or expected[2] or expected[0] != source["mode"] or expected[1] != (retained_root / path).read_bytes():
            _fail(f"retained source differs from authenticated Git tree: {path}")
        current = _relative_file(ROOT, path, "current selected source")
        if current.read_bytes() != expected[1] or stat.S_IMODE(current.stat().st_mode) != expected[0]:
            _fail(f"current selected source differs from retained native receipt: {path}")
    validate_source_contract(retained_root)
    validate_source_contract(ROOT)
    return {"revision": revision, "tree": tree, "content_sha256": digest, "clean": True, "paths": retained}


def _validate_current_tracked_source(revision: str, digest: str, files: Mapping[str, tuple[int, bytes, bool]]) -> None:
    """Admit the trusted checkout's exact recorded HEAD and every tracked byte/mode."""

    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_utmpx_receipt as utmpx

    try:
        if utmpx.local_git_head(ROOT) != revision:
            _fail("current Git HEAD differs from retained source authority")
    except utmpx.ReceiptError as error:
        raise LocaleAliasReceiptError("current Git HEAD is unreadable") from error
    current_digest = hashlib.sha256()
    for name, (mode, expected, symlink) in sorted(files.items()):
        path = ROOT / name
        try:
            metadata = path.lstat()
        except OSError as error:
            raise LocaleAliasReceiptError(f"current tracked source is absent: {name}") from error
        if stat.S_IMODE(metadata.st_mode) != mode:
            _fail(f"current tracked source mode differs: {name}")
        if symlink:
            if not stat.S_ISLNK(metadata.st_mode):
                _fail(f"current tracked source kind differs: {name}")
            actual = os.fsencode(os.readlink(path))
        else:
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                _fail(f"current tracked source kind differs: {name}")
            actual = path.read_bytes()
        if actual != expected:
            _fail(f"current tracked source differs from retained authority: {name}")
        current_digest.update(name.encode() + b"\0" + str(mode).encode() + b"\0")
        current_digest.update(hashlib.sha256(actual).digest())
    if current_digest.hexdigest() != digest:
        _fail("current tracked source digest differs from retained authority")


def _expected_collector_commands(output_relative: str) -> list[tuple[str, list[str]]]:
    preparation = _mount(f"{output_relative}/{STATIC_PREPARATION_DIRECTORY}")
    static = _mount(f"{output_relative}/{STATIC_PRODUCT_DIRECTORY}")
    dynamic = _mount(f"{output_relative}/{DYNAMIC_PRODUCT_DIRECTORY}")
    runner = _mount(RUNNER_PATH)
    raw = _mount(f"{output_relative}/{RUNNER_DIRECTORY}")
    return [
        ("prepare-static", ["/usr/bin/python3", "-B", _mount(STATIC_PREPARATION_OWNER_PATH), "prepare", preparation]),
        ("build-dynamic", ["/usr/bin/python3", "-B", _mount(DYNAMIC_BUILDER_PATH), "--output", dynamic]),
        ("locale-alias-runner", [runner, "--receipt-dir", raw, "--static-sysroot", static, dynamic]),
    ]


def _raw_collector_commands(root: Path, output_relative: str) -> list[dict[str, object]]:
    collector = _relative_directory(root, "collector", "collector raw")
    expected_names = {
        f"{role}.{suffix}"
        for role, _argv in _expected_collector_commands(output_relative)
        for suffix in ("argv.json", "cwd", "environment.json", "stdin", "launcher.json", "stdout", "stderr", "status")
    }
    actual_names = {path.name for path in collector.iterdir()}
    if actual_names != expected_names:
        _fail("collector raw file roster changed")
    environment = _collector_environment(output_relative)
    launcher = _collector_launcher(output_relative)
    records: list[dict[str, object]] = []
    for role, argv in _expected_collector_commands(output_relative):
        argv_path = collector / f"{role}.argv.json"
        received_argv = _strict_json(argv_path, f"collector argv {role}")
        cwd_path = collector / f"{role}.cwd"
        if cwd_path.is_symlink() or not cwd_path.is_file() or cwd_path.read_bytes() != (SOURCE_MOUNT + "\n").encode():
            _fail(f"collector cwd changed: {role}")
        status_path = collector / f"{role}.status"
        records.append({
            "schema": COMMAND_SCHEMA, "role": role, "cwd": SOURCE_MOUNT,
            "argv": received_argv, "status": 0 if status_path.read_bytes() == b"0\n" else -1,
            "environment": environment, "stdin": "/dev/null", "launcher": launcher,
            "stdout": _identity(root, collector / f"{role}.stdout"),
            "stderr": _identity(root, collector / f"{role}.stderr"),
            "status_stream": _identity(root, status_path),
            "cwd_stream": _identity(root, cwd_path),
            "environment_stream": _identity(root, collector / f"{role}.environment.json"),
            "stdin_stream": _identity(root, collector / f"{role}.stdin"),
            "launcher_stream": _identity(root, collector / f"{role}.launcher.json"),
        })
    for record, (role, argv) in zip(records, _expected_collector_commands(output_relative)):
        validate_command_record(root, record, role=role, cwd=SOURCE_MOUNT, argv=argv, environment=environment, launcher=launcher)
    return records


def _validate_collector_commands(root: Path, output_relative: str, value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != 3:
        _fail("collector command roster changed")
    actual = _raw_collector_commands(root, output_relative)
    if value != actual:
        _fail("collector command records do not name the retained raw streams")
    return actual


def _validate_execution_tools(
    root: Path,
    output_relative: str,
    source: Mapping[str, object],
    image: Mapping[str, object],
    products: Mapping[str, object],
    collector: Sequence[Mapping[str, object]],
    runner: Sequence[Mapping[str, object]],
) -> None:
    """Join every recorded executable and launcher to a retained input policy."""

    source_entries = {item["path"]: item for item in source["paths"]}
    image_files = image["files"]
    assert isinstance(image_files, Mapping)
    product_prefixes = {
        name: _mount(f"{output_relative}/{directory}") + "/"
        for name, directory in (("static", STATIC_PRODUCT_DIRECTORY), ("dynamic", DYNAMIC_PRODUCT_DIRECTORY))
    }

    def require_program(program: object, label: str) -> None:
        if not isinstance(program, str) or not program:
            _fail(f"{label} program is malformed")
        if program.startswith(SOURCE_MOUNT + "/"):
            relative = program[len(SOURCE_MOUNT) + 1:]
            if relative in {STATIC_PREPARATION_OWNER_PATH, STATIC_BUILDER_PATH, DYNAMIC_BUILDER_PATH, RUNNER_PATH}:
                retained = _identity(root, root / "inputs/source" / relative)
                if source_entries.get(relative) != retained:
                    _fail(f"{label} source tool differs from retained source")
                return
            product_name = next((name for name, prefix in product_prefixes.items() if program.startswith(prefix)), None)
            if product_name is not None:
                prefix = product_prefixes[product_name]
                product_relative = program[len(prefix):]
                directory = STATIC_PRODUCT_DIRECTORY if product_name == "static" else DYNAMIC_PRODUCT_DIRECTORY
                retained_path = f"{directory}/{product_relative}"
                retained = _relative_file(root, retained_path, f"{label} product tool")
                tree = products[product_name]["tree"]
                if not any(entry.get("kind") == "file" and entry.get("path") == retained_path for entry in tree):
                    _fail(f"{label} product tool is absent from retained product tree")
                _identity(root, retained)
                return
            _fail(f"{label} executable escapes retained source or product")
        if program not in image_files:
            _fail(f"{label} executable is not a retained image input")
        item = image_files[program]
        assert isinstance(item, Mapping)
        retained = item["retained"]
        assert isinstance(retained, Mapping)
        _file_record(root, retained, f"{label} image tool")

    require_program("/bin/bash", "runner interpreter")
    require_program("/bin/sh", "oracle compiler interpreter")
    require_program("/usr/bin/gcc", "oracle compiler backend")
    for record in [*collector, *runner]:
        require_program(record["argv"][0] if isinstance(record.get("argv"), list) and record["argv"] else None,
                        f"{record.get('role', 'recorded')} command")
        launcher = record.get("launcher")
        if not isinstance(launcher, list) or len(launcher) < 2:
            _fail("recorded launcher is malformed")
        require_program(launcher[0], f"{record.get('role', 'recorded')} launcher")
        require_program(launcher[-2], f"{record.get('role', 'recorded')} timeout")


def validate_report(root: Path, report_path: Path) -> dict[str, object]:
    """Replay a completed receipt from retained bytes without launching tools."""

    root = root.resolve()
    if report_path.is_symlink() or not report_path.is_file():
        _fail("receipt report is not a physical regular file")
    report_path = report_path.resolve()
    try:
        receipt_root = report_path.parent
        output_relative = receipt_root.relative_to(root).as_posix()
    except ValueError as error:
        raise LocaleAliasReceiptError("receipt report is outside supplied checkout") from error
    _output_relative(root, receipt_root)
    report_identity = _identity(receipt_root, report_path)
    report = _strict_json(report_path, "locale alias receipt report")
    expected = {"schema", "status", "mode_policy", "image_inputs", "source_before", "source_after", "source_contract", "products", "collector_commands", "runner_commands", "snapshots", "artifacts", "runtime", "symbols", "nonclaims"}
    record = _exact_mapping(report, expected, "locale alias receipt report")
    if (record["schema"] != SCHEMA or record["status"] != STATUS or record["mode_policy"] != MODE_POLICY
            or record["nonclaims"] != list(NONCLAIMS)):
        _fail("locale alias receipt status changed")
    if record["source_before"] != record["source_after"]:
        _fail("source changed during locale alias collection")
    source = _validate_source_seal(receipt_root, record["source_before"], "inputs/source")
    after_source = _validate_source_seal(receipt_root, record["source_after"], "source-after/inputs/source")
    if source != after_source:
        _fail("retained source before/after bytes differ")
    source_contract = validate_source_contract(receipt_root / "inputs/source")
    if record["source_contract"] != source_contract:
        _fail("source alias contract observation changed")
    image = _validate_image_inputs(receipt_root, record["image_inputs"])
    products = _validate_products(root, receipt_root, record["products"], source, image)
    collector_commands = _validate_collector_commands(receipt_root, output_relative, record["collector_commands"])
    runner_commands = _runner_records(receipt_root, output_relative, record["runner_commands"])
    _validate_execution_tools(receipt_root, output_relative, source, image, products, collector_commands, runner_commands)
    artifacts = _validate_artifacts(receipt_root, record["artifacts"])
    dynamic_links = _validate_dynamic_executable_link_sidecars(receipt_root, image)
    snapshots = {name: _validate_snapshot(receipt_root, record["snapshots"].get(name) if isinstance(record["snapshots"], Mapping) else None, name)
                 for name in ("before", "after")}
    if snapshots["before"]["records"] != snapshots["after"]["records"]:
        _fail("runner input snapshots differ")
    runtime = _validate_runtime_and_headers(receipt_root)
    if record["runtime"] != runtime:
        _fail("runtime/header observation changed")
    symbols = _validate_symbol_observation(receipt_root)
    if record["symbols"] != symbols:
        _fail("symbol observation changed")
    _public_replay_exit_recheck(
        root, receipt_root, report_path, report_identity, record, output_relative, source, after_source,
        source_contract, image, products, collector_commands, runner_commands, artifacts, dynamic_links, snapshots, runtime, symbols,
    )
    return {
        "source": source,
        "image_inputs": image,
        "products": products,
        "collector_commands": collector_commands,
        "runner_commands": runner_commands,
        "artifacts": artifacts,
        "runtime": runtime,
        "symbols": symbols,
        "status": STATUS,
    }


def _public_replay_exit_recheck(
    checkout_root: Path,
    receipt_root: Path,
    report_path: Path,
    report_identity: Mapping[str, object],
    record: Mapping[str, object],
    output_relative: str,
    source: Mapping[str, object],
    after_source: Mapping[str, object],
    source_contract: Mapping[str, object],
    image: Mapping[str, object],
    products: Mapping[str, object],
    collector_commands: Sequence[Mapping[str, object]],
    runner_commands: Sequence[Mapping[str, object]],
    artifacts: Mapping[str, object],
    dynamic_links: Mapping[str, object],
    snapshots: Mapping[str, object],
    runtime: Mapping[str, object],
    symbols: Mapping[str, object],
) -> None:
    """Repeat the public reader's finite reconstruction without starting a process."""

    if _identity(receipt_root, report_path) != report_identity:
        _fail("report changed during process-free replay")
    if _strict_json(report_path, "locale alias receipt report") != record:
        _fail("report content changed during process-free replay")
    source_again = _validate_source_seal(receipt_root, record["source_before"], "inputs/source")
    after_again = _validate_source_seal(receipt_root, record["source_after"], "source-after/inputs/source")
    if source_again != source or after_again != after_source:
        _fail("source reconstruction changed during process-free replay")
    if validate_source_contract(receipt_root / "inputs/source") != source_contract:
        _fail("source contract changed during process-free replay")
    image_again = _validate_image_inputs(receipt_root, record["image_inputs"])
    products_again = _validate_products(checkout_root, receipt_root, record["products"], source_again, image_again)
    collector_again = _validate_collector_commands(receipt_root, output_relative, record["collector_commands"])
    runner_again = _runner_records(receipt_root, output_relative, record["runner_commands"])
    _validate_execution_tools(receipt_root, output_relative, source_again, image_again, products_again, collector_again, runner_again)
    artifacts_again = _validate_artifacts(receipt_root, record["artifacts"])
    dynamic_links_again = _validate_dynamic_executable_link_sidecars(receipt_root, image_again)
    snapshots_again = {name: _validate_snapshot(receipt_root, record["snapshots"].get(name) if isinstance(record["snapshots"], Mapping) else None, name)
                       for name in ("before", "after")}
    runtime_again = _validate_runtime_and_headers(receipt_root)
    symbols_again = _validate_symbol_observation(receipt_root)
    if (image_again != image or products_again != products or list(collector_again) != list(collector_commands)
            or list(runner_again) != list(runner_commands) or artifacts_again != artifacts or dynamic_links_again != dynamic_links
            or snapshots_again != snapshots or runtime_again != runtime or symbols_again != symbols):
        _fail("receipt reconstruction changed during process-free replay")


def _require_native_collection(root: Path, output: Path) -> str:
    if root.resolve() != Path(SOURCE_MOUNT):
        _fail("native collection requires the pinned /workspace mount")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        _fail("native collection requires Linux/x86-64")
    output_relative = _output_relative(root, output)
    if output.exists() or output.is_symlink():
        _fail("locale alias receipt output must be fresh")
    return output_relative


def _run(root: Path, receipt_root: Path, role: str, argv: list[str], *, env: Mapping[str, str]) -> dict[str, object]:
    """Run one collector action through the same sealed launcher as the runner."""

    output_relative = _output_relative(root, receipt_root)
    environment = _collector_environment(output_relative)
    launcher = _collector_launcher(output_relative)
    if dict(env) != {**COMMAND_ENVIRONMENT, "TMPDIR": str(receipt_root / "tmp"), "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
                     **COLLECTOR_GIT_SAFE_DIRECTORY}:
        _fail("collector environment differs from its closed contract")
    raw = receipt_root / "collector" / role
    raw.parent.mkdir(parents=True, exist_ok=True)
    paths = {suffix: raw.with_suffix("." + suffix) for suffix in (
        "stdout", "stderr", "status", "argv.json", "cwd", "environment.json", "stdin", "launcher.json",
    )}
    paths["argv.json"].write_text(json.dumps(argv, separators=(",", ":")) + "\n", encoding="utf-8")
    paths["cwd"].write_text(SOURCE_MOUNT + "\n", encoding="utf-8")
    paths["environment.json"].write_text(json.dumps(environment, separators=(",", ":")) + "\n", encoding="utf-8")
    paths["stdin"].write_bytes(b"/dev/null\n")
    paths["launcher.json"].write_text(json.dumps(launcher, separators=(",", ":")) + "\n", encoding="utf-8")
    completed = subprocess.run(
        [*launcher, *argv], cwd=root, env=dict(env), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    paths["stdout"].write_bytes(completed.stdout)
    paths["stderr"].write_bytes(completed.stderr)
    paths["status"].write_bytes(f"{completed.returncode}\n".encode("ascii"))
    record = {
        "schema": COMMAND_SCHEMA, "role": role, "cwd": SOURCE_MOUNT, "argv": argv,
        "status": completed.returncode, "environment": environment, "stdin": "/dev/null", "launcher": launcher,
        "stdout": _identity(receipt_root, paths["stdout"]), "stderr": _identity(receipt_root, paths["stderr"]),
        "status_stream": _identity(receipt_root, paths["status"]), "cwd_stream": _identity(receipt_root, paths["cwd"]), "environment_stream": _identity(receipt_root, paths["environment.json"]),
        "stdin_stream": _identity(receipt_root, paths["stdin"]), "launcher_stream": _identity(receipt_root, paths["launcher.json"]),
    }
    if completed.returncode != 0:
        _fail(f"native command failed and retained raw output: {role}")
    return record


def _source_state(value: Mapping[str, object]) -> dict[str, object]:
    return {name: value[name] for name in ("revision", "tree", "content_sha256", "clean")}


def _final_transaction_recheck(
    root: Path,
    receipt_root: Path,
    source: Mapping[str, object],
    image: Mapping[str, object],
    products: Mapping[str, object],
    collector_commands: Sequence[Mapping[str, object]],
    runner_commands: Sequence[Mapping[str, object]],
    output_relative: str,
) -> None:
    """Recheck every mutable collection input after report construction."""

    if _live_source_state(root) != _source_state(source):
        _fail("source changed after locale alias report construction")
    if _validate_image_inputs(receipt_root, image) != image:
        _fail("image inputs changed after locale alias report construction")
    if _validate_products(root, receipt_root, products, source, image) != products:
        _fail("products changed after locale alias report construction")
    if _raw_collector_commands(receipt_root, output_relative) != list(collector_commands):
        _fail("collector raw streams changed after locale alias report construction")
    if _raw_runner_records(receipt_root, output_relative) != list(runner_commands):
        _fail("runner raw streams changed after locale alias report construction")
    _validate_dynamic_executable_link_sidecars(receipt_root, image)


def collect(root: Path, output: Path) -> dict[str, object]:
    """Build current products and run the retained locale alias matrix once."""

    root = root.resolve()
    output = output.absolute()
    output_relative = _require_native_collection(root, output)
    output.mkdir(parents=True)
    try:
        before = _capture_source_phase(root, output, "inputs/source")
        source_state = _source_state(before)
        image_inputs = _copy_image_inputs(root, output)
        env = {
            "PATH": COMMAND_PATH,
            "TMPDIR": str(output / "tmp"), "LC_ALL": "C", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
            **COLLECTOR_GIT_SAFE_DIRECTORY,
        }
        (output / "tmp").mkdir(mode=0o700)
        collector_commands = []
        if _live_source_state(root) != source_state:
            _fail("source changed before static product construction")
        collector_commands.append(_run(root, output, "prepare-static", _expected_collector_commands(output_relative)[0][1], env=env))
        if _live_source_state(root) != source_state:
            _fail("source changed during static product construction")
        collector_commands.append(_run(root, output, "build-dynamic", _expected_collector_commands(output_relative)[1][1], env=env))
        if _live_source_state(root) != source_state:
            _fail("source changed during dynamic product construction")
        collector_commands.append(_run(root, output, "locale-alias-runner", _expected_collector_commands(output_relative)[2][1], env=env))
        after = _capture_source_phase(root, output, "source-after/inputs/source", source_state)
        if before != after:
            _fail("source changed during locale alias collection")
        raw_commands = _raw_runner_records(output, output_relative)
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        import owned_posix_product_evidence as products
        static_product = output / STATIC_PRODUCT_DIRECTORY
        dynamic_product = output / DYNAMIC_PRODUCT_DIRECTORY
        static_manifest = products._validate_static_product(static_product)[0]
        dynamic_manifest = products._validate_dynamic_product(dynamic_product)[0]
        product_records = {
            "static": {
                "tree": _tree_records(output, STATIC_PRODUCT_DIRECTORY),
                "manifest": _identity(output, static_manifest),
                "preparation": {
                    "directory": STATIC_PREPARATION_DIRECTORY,
                    "tree": _tree_records(output, STATIC_PREPARATION_DIRECTORY),
                    "record": _identity(output, output / STATIC_PREPARATION_DIRECTORY / "preparation.json"),
                },
            },
            "dynamic": {
                "tree": _tree_records(output, DYNAMIC_PRODUCT_DIRECTORY),
                "manifest": _identity(output, dynamic_manifest),
                "source_before": before,
                "source_after": before,
            },
        }
        dynamic_state = dynamic_product / "share/crabc/dynamic-product-state.json"
        product_records["dynamic"]["state"] = _identity(output, dynamic_state)
        report = {
            "schema": SCHEMA,
            "status": STATUS,
            "mode_policy": MODE_POLICY,
            "image_inputs": image_inputs,
            "source_before": before,
            "source_after": after,
            "source_contract": validate_source_contract(output / "inputs/source"),
            "products": product_records,
            "collector_commands": collector_commands,
            "runner_commands": raw_commands,
            "snapshots": {name: _snapshot(output, name) for name in ("before", "after")},
            "artifacts": _artifacts(output),
            "runtime": _validate_runtime_and_headers(output),
            "symbols": _validate_symbol_observation(output),
            "nonclaims": list(NONCLAIMS),
        }
        report_path = output / "report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validate_report(root, report_path)
        _final_transaction_recheck(root, output, before, image_inputs, product_records, collector_commands, raw_commands, output_relative)
        return report
    except Exception:
        # The fresh root deliberately remains available with raw command output
        # when compilation, product construction, or the runtime matrix fails.
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    collect_parser = subcommands.add_parser("collect")
    collect_parser.add_argument("--output", type=Path, required=True)
    validate_parser = subcommands.add_parser("validate-report")
    validate_parser.add_argument("report", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "collect":
            result = collect(ROOT, arguments.output)
        else:
            result = validate_report(ROOT, arguments.report)
    except LocaleAliasReceiptError as error:
        print(f"locale alias receipt: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
