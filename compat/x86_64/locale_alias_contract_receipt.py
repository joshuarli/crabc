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
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
SOURCE_MOUNT = "/workspace"
SCHEMA = "crabc.x86_64-locale-alias-contract-receipt/v1"
COMMAND_SCHEMA = "crabc.x86_64-locale-alias-contract-command/v1"
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
    "compat/x86_64/owned_dynamic_receipt.py",
    "compat/x86_64/crabc_cc_owned_dynamic.py",
    "compat/x86_64/owned_static_sysroot_package.py",
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
    record = _exact_mapping(value, {"path", "bytes", "sha256"}, label)
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
    return {"path": record["path"], "bytes": record["bytes"], "sha256": record["sha256"]}


def _identity(root: Path, path: Path) -> dict[str, object]:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise LocaleAliasReceiptError(f"retained path is outside receipt root: {path}") from error
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        _fail(f"retained path is not a physical regular file: {relative}")
    return {"path": relative, "bytes": metadata.st_size, "sha256": _sha256(path)}


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
) -> dict[str, object]:
    """Validate one successful command and its three immutable raw streams."""

    record = _exact_mapping(
        value,
        {"schema", "role", "cwd", "argv", "status", "stdout", "stderr", "status_stream"},
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
    result = {name: _file_record(root, record[name], f"retained command {name}")
              for name in ("stdout", "stderr", "status_stream")}
    status_path = _relative_file(root, result["status_stream"]["path"], "retained command status")
    if status_path.read_bytes() != b"0\n":
        _fail("retained command raw status stream changed")
    return {"role": role, "argv": list(argv), "cwd": cwd, "status": 0, **result}


def source_records(root: Path, paths: Iterable[str]) -> list[dict[str, object]]:
    """Record an ordered finite source roster relative to one physical root."""

    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in paths:
        if not isinstance(value, str) or not value or value in seen:
            _fail("source roster is not finite and unique")
        seen.add(value)
        path = _relative_file(root, value, "source")
        records.append({"path": value, "bytes": path.stat().st_size, "sha256": _sha256(path)})
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
    static = _mount(f"{output_relative}/products/static")
    dynamic = _mount(f"{output_relative}/products/dynamic")
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
        add(f"{executable}-header", ["readelf", "-h", f"{work}/{executable}"])
    add("oracle-static-run", ["env", "-i", "TZ=UTC", f"{work}/oracle-static"])
    add("candidate-static-run", ["env", "-i", "TZ=UTC", f"{work}/candidate-static"])
    add("candidate-static-pie-run", ["env", "-i", "TZ=UTC", f"{work}/candidate-static-pie"])
    for mode in ("pie", "non-pie"):
        for entry in ("kernel", "direct"):
            oracle = ["chroot", f"{work}/oracle-dynamic-root"]
            candidate = ["chroot", f"{work}/candidate-dynamic-root"]
            if entry == "kernel":
                oracle.append(f"/consumer-{mode}")
                candidate.append(f"/consumer-{mode}")
            else:
                oracle.extend(["/lib/ld-musl-x86_64.so.1", f"/consumer-{mode}"])
                candidate.extend(["/lib/ld-crabc-x86_64.so.1", f"/consumer-{mode}"])
            add(f"oracle-dynamic-{mode}-{entry}", oracle)
            add(f"candidate-dynamic-{mode}-{entry}", candidate)
    add("oracle-static-symbols", ["readelf", "-Ws", "/opt/musl-1.2.6/lib/libc.a"])
    add("oracle-dynamic-symbols", ["readelf", "--dyn-syms", "-W", "/opt/musl-1.2.6/lib/libc.so"])
    add("oracle-shared-symbols", ["readelf", "-Ws", "/opt/musl-1.2.6/lib/libc.so"])
    add("candidate-static-symbols", ["readelf", "-Ws", f"{static}/usr/lib/libc.a"])
    add("candidate-dynamic-symbols", ["readelf", "--dyn-syms", "-W", f"{dynamic}/usr/lib/libc.so"])
    add("candidate-shared-symbols", ["readelf", "-Ws", f"{dynamic}/usr/lib/libc.so"])
    add("executable-dynamic-pie-symbols", ["readelf", "--dyn-syms", "-W", f"{work}/candidate-dynamic-pie"])
    add("executable-dynamic-non-pie-symbols", ["readelf", "--dyn-syms", "-W", f"{work}/candidate-dynamic-non-pie"])
    add("alias-symbol-observation", ["python3", "-B", symbol_reader, contract,
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
    expected = {f"{stem}.{suffix}" for stem in RUNNER_STEMS for suffix in ("argv.json", "cwd", "stdout", "stderr", "status")}
    expected.update({"before.sha256", "after.sha256", "alias-observation.json"})
    generated = {
        "probe.o", "oracle-static", "candidate-static", "candidate-static-pie",
        "oracle-dynamic-pie", "oracle-dynamic-non-pie",
        "candidate-dynamic-pie", "candidate-dynamic-non-pie",
        "oracle-dynamic-root", "candidate-dynamic-root",
    }
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
            "stdout": _identity(root, raw / f"{stem}.stdout"),
            "stderr": _identity(root, raw / f"{stem}.stderr"),
            "status_stream": _identity(root, raw / f"{stem}.status"),
        })
    for record, (role, argv) in zip(records, _runner_plan(output_relative)):
        validate_command_record(root, record, role=role, cwd=SOURCE_MOUNT, argv=argv)
    return records


def _snapshot(root: Path, name: str) -> dict[str, object]:
    path = _relative_file(root, f"{RUNNER_DIRECTORY}/{name}.sha256", f"runner {name} snapshot")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise LocaleAliasReceiptError(f"runner {name} snapshot is invalid") from error
    expected_names = (PROBE_PATH, CONTRACT_PATH, SYMBOL_READER_PATH, "products/static/usr/lib/libc.a", "products/dynamic/usr/lib/libc.so")
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
    return {"path": f"{RUNNER_DIRECTORY}/{name}.sha256", "records": records, "sha256": _sha256(path)}


def _validate_snapshot(root: Path, value: object, name: str) -> dict[str, object]:
    record = _exact_mapping(value, {"path", "records", "sha256"}, f"runner {name} snapshot")
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
    names = (
        "probe.o", "oracle-static", "candidate-static", "candidate-static-pie",
        "oracle-dynamic-pie", "oracle-dynamic-non-pie",
        "candidate-dynamic-pie", "candidate-dynamic-non-pie",
    )
    return {name: _identity(root, raw / name) for name in names}


def _validate_artifacts(root: Path, value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, Mapping):
        _fail("compiled artifact identity is malformed")
    actual = _artifacts(root)
    if value != actual:
        _fail("compiled object or linked executable bytes changed")
    return actual


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
        if candidate.is_symlink():
            target = os.readlink(candidate)
            records.append({"path": candidate.relative_to(root).as_posix(), "kind": "symlink", "target": target})
        elif candidate.is_file():
            identity = _identity(root, candidate)
            records.append({"path": identity["path"], "kind": "file", "bytes": identity["bytes"], "sha256": identity["sha256"]})
        elif candidate.is_dir():
            continue
        else:
            _fail(f"product has unsupported filesystem entry: {candidate}")
    if not records:
        _fail(f"{directory} product is empty")
    return records


def _validate_products(root: Path, value: object) -> dict[str, object]:
    expected = {"static", "dynamic"}
    records = _exact_mapping(value, expected, "retained products")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import owned_posix_product_evidence as products

    result: dict[str, object] = {}
    for name in ("static", "dynamic"):
        item = _exact_mapping(records[name], {"tree", "manifest"}, f"{name} retained product")
        current_tree = _tree_records(root, f"products/{name}")
        if item["tree"] != current_tree:
            _fail(f"{name} retained product tree changed")
        product = root / "products" / name
        manifest_path, _details = (products._validate_static_product(product) if name == "static"
                                   else products._validate_dynamic_product(product))
        manifest = _identity(root, manifest_path)
        if item["manifest"] != manifest:
            _fail(f"{name} retained product manifest changed")
        result[name] = {"tree": current_tree, "manifest": manifest}
    return result


def _oracle_records(root: Path) -> dict[str, object]:
    oracle = _relative_directory(root, "inputs/oracle", "pinned musl")
    expected = {"lib/libc.a", "lib/libc.so", ".crabc-oracle", "lib/musl-gcc.specs", "bin/crabc-x86_64-musl-gcc"}
    actual = {path.relative_to(oracle).as_posix() for path in oracle.rglob("*") if path.is_file()}
    if actual != expected:
        _fail("pinned musl retained file roster changed")
    metadata = (oracle / ".crabc-oracle").read_text(encoding="ascii")
    expected_metadata = (
        "format=crabc-pinned-musl-oracle-v1\n"
        "version=1.2.6\n"
        f"source_sha256={MUSL_SOURCE_SHA256}\n"
        f"fallback_revision={MUSL_REVISION}\n"
        "architecture=x86_64\n"
    )
    if metadata != expected_metadata:
        _fail("pinned musl metadata changed")
    return {path: _identity(root, oracle / path) for path in sorted(expected)}


def _validate_source_seal(root: Path, value: object, source_directory: str) -> list[dict[str, object]]:
    record = _exact_mapping(value, {"revision", "clean", "paths"}, "source seal")
    if record["clean"] is not True:
        _fail("source seal is not clean")
    if (not isinstance(record["revision"], str) or len(record["revision"]) != 40
            or any(character not in "0123456789abcdef" for character in record["revision"])):
        _fail("source revision is invalid")
    if not isinstance(record["paths"], list):
        _fail("source seal paths are invalid")
    retained_root = _relative_directory(root, source_directory, "retained source")
    retained = source_records(retained_root, SELECTED_SOURCES)
    if record["paths"] != retained:
        _fail("retained source bytes changed")
    current = source_records(ROOT, SELECTED_SOURCES)
    if retained != current:
        _fail("current selected source differs from retained native receipt")
    validate_source_contract(retained_root)
    validate_source_contract(ROOT)
    return retained


def _expected_collector_commands(output_relative: str) -> list[tuple[str, list[str]]]:
    static = _mount(f"{output_relative}/products/static")
    dynamic = _mount(f"{output_relative}/products/dynamic")
    runner = _mount(RUNNER_PATH)
    raw = _mount(f"{output_relative}/{RUNNER_DIRECTORY}")
    return [
        ("build-static", ["python3", "-B", _mount(STATIC_BUILDER_PATH), "--output", static]),
        ("build-dynamic", ["python3", "-B", _mount(DYNAMIC_BUILDER_PATH), "--output", dynamic]),
        ("locale-alias-runner", [runner, "--receipt-dir", raw, "--static-sysroot", static, dynamic]),
    ]


def _raw_collector_commands(root: Path, output_relative: str) -> list[dict[str, object]]:
    collector = _relative_directory(root, "collector", "collector raw")
    expected_names = {
        f"{role}.{suffix}"
        for role, _argv in _expected_collector_commands(output_relative)
        for suffix in ("argv.json", "cwd", "stdout", "stderr", "status")
    }
    actual_names = {path.name for path in collector.iterdir()}
    if actual_names != expected_names:
        _fail("collector raw file roster changed")
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
            "stdout": _identity(root, collector / f"{role}.stdout"),
            "stderr": _identity(root, collector / f"{role}.stderr"),
            "status_stream": _identity(root, status_path),
        })
    for record, (role, argv) in zip(records, _expected_collector_commands(output_relative)):
        validate_command_record(root, record, role=role, cwd=SOURCE_MOUNT, argv=argv)
    return records


def _validate_collector_commands(root: Path, output_relative: str, value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != 3:
        _fail("collector command roster changed")
    actual = _raw_collector_commands(root, output_relative)
    if value != actual:
        _fail("collector command records do not name the retained raw streams")
    return actual


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
    report = _strict_json(report_path, "locale alias receipt report")
    expected = {"schema", "status", "oracle", "source_before", "source_after", "source_contract", "products", "collector_commands", "runner_commands", "snapshots", "artifacts", "runtime", "symbols", "nonclaims"}
    record = _exact_mapping(report, expected, "locale alias receipt report")
    if record["schema"] != SCHEMA or record["status"] != STATUS or record["nonclaims"] != list(NONCLAIMS):
        _fail("locale alias receipt status changed")
    if record["source_before"] != record["source_after"]:
        _fail("source changed during locale alias collection")
    sources = _validate_source_seal(receipt_root, record["source_before"], "inputs/source")
    after_sources = _validate_source_seal(receipt_root, record["source_after"], "source-after/inputs/source")
    if sources != after_sources:
        _fail("retained source before/after bytes differ")
    source_contract = validate_source_contract(receipt_root / "inputs/source")
    if record["source_contract"] != source_contract:
        _fail("source alias contract observation changed")
    oracle = _oracle_records(receipt_root)
    if record["oracle"] != oracle:
        _fail("pinned musl receipt changed")
    products = _validate_products(receipt_root, record["products"])
    collector_commands = _validate_collector_commands(receipt_root, output_relative, record["collector_commands"])
    runner_commands = _runner_records(receipt_root, output_relative, record["runner_commands"])
    artifacts = _validate_artifacts(receipt_root, record["artifacts"])
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
    return {
        "sources": sources,
        "products": products,
        "oracle": oracle,
        "collector_commands": collector_commands,
        "runner_commands": runner_commands,
        "artifacts": artifacts,
        "runtime": runtime,
        "symbols": symbols,
        "status": STATUS,
    }


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
    raw = receipt_root / "collector" / role
    raw.parent.mkdir(parents=True, exist_ok=True)
    stdout = raw.with_suffix(".stdout")
    stderr = raw.with_suffix(".stderr")
    status = raw.with_suffix(".status")
    argv_path = raw.with_suffix(".argv.json")
    cwd_path = raw.with_suffix(".cwd")
    argv_path.write_text(json.dumps(argv, separators=(",", ":")) + "\n", encoding="utf-8")
    cwd_path.write_text(SOURCE_MOUNT + "\n", encoding="utf-8")
    completed = subprocess.run(argv, cwd=root, env=dict(env), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    stdout.write_bytes(completed.stdout)
    stderr.write_bytes(completed.stderr)
    status.write_bytes(f"{completed.returncode}\n".encode("ascii"))
    record = {
        "schema": COMMAND_SCHEMA, "role": role, "cwd": SOURCE_MOUNT, "argv": argv,
        "status": completed.returncode,
        "stdout": _identity(receipt_root, stdout), "stderr": _identity(receipt_root, stderr), "status_stream": _identity(receipt_root, status),
    }
    if completed.returncode != 0:
        _fail(f"native command failed and retained raw output: {role}")
    return record


def _source_seal(root: Path, receipt_root: Path) -> dict[str, object]:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=no"], cwd=root, text=True)
    if dirty:
        _fail("native collection requires a clean tracked source")
    source_root = receipt_root / "inputs/source"
    for relative in SELECTED_SOURCES:
        _copy_regular(root / relative, source_root / relative)
    return {"revision": revision, "clean": True, "paths": source_records(source_root, SELECTED_SOURCES)}


def _copy_oracle(receipt_root: Path) -> None:
    copied = {
        "lib/libc.a": ORACLE_ROOT / "lib/libc.a",
        "lib/libc.so": ORACLE_ROOT / "lib/libc.so",
        ".crabc-oracle": ORACLE_ROOT / ".crabc-oracle",
        "lib/musl-gcc.specs": ORACLE_ROOT / "lib/musl-gcc.specs",
        "bin/crabc-x86_64-musl-gcc": Path(ORACLE_COMPILER),
    }
    for relative, source in copied.items():
        _copy_regular(source, receipt_root / "inputs/oracle" / relative)


def collect(root: Path, output: Path) -> dict[str, object]:
    """Build current products and run the retained locale alias matrix once."""

    root = root.resolve()
    output = output.absolute()
    output_relative = _require_native_collection(root, output)
    output.mkdir(parents=True)
    try:
        before = _source_seal(root, output)
        _copy_oracle(output)
        env = {
            "PATH": "/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TMPDIR": str(output / "tmp"), "LC_ALL": "C", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
        }
        (output / "tmp").mkdir(mode=0o700)
        collector_commands = []
        collector_commands.append(_run(root, output, "build-static", _expected_collector_commands(output_relative)[0][1], env=env))
        collector_commands.append(_run(root, output, "build-dynamic", _expected_collector_commands(output_relative)[1][1], env=env))
        collector_commands.append(_run(root, output, "locale-alias-runner", _expected_collector_commands(output_relative)[2][1], env=env))
        after = _source_seal(root, output / "source-after")
        if before != after:
            _fail("source changed during locale alias collection")
        raw_commands = _raw_runner_records(output, output_relative)
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        import owned_posix_product_evidence as products
        product_records = {
            name: {"tree": _tree_records(output, f"products/{name}"), "manifest": _identity(output, manifest)}
            for name, manifest in (("static", products._validate_static_product(output / "products/static")[0]),
                                   ("dynamic", products._validate_dynamic_product(output / "products/dynamic")[0]) )
        }
        report = {
            "schema": SCHEMA,
            "status": STATUS,
            "oracle": _oracle_records(output),
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
