#!/usr/bin/env python3
"""Retain pinned-musl evidence for header callables declared without providers.

The checked header-callable disposition names the finite C declaration group
whose pinned x86 musl headers expose a function while the same pinned musl
``libc.a`` and shared ``libc.so`` provide no global or weak definition.  This
tool audits that exact checked group.  It is deliberately a structural oracle
finding: it does not supply a crabc implementation, test a function body, or
close a family or public-support claim.

Every invocation keeps a self-describing receipt below the supplied native
scratch directory.  A failed command is recorded and fails the judgment; it
can never be interpreted as a missing provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
INVENTORY_SCHEMA = "crabc.x86_64-header-callable-inventory-report/v2"
NO_PROVIDER_RESOLUTION = "oracle-declared-no-provider"
MUSL_VERSION = "1.2.6"
MUSL_SHA256 = "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
MUSL_REVISION = "9fa28ece75d8a2191de7c5bb53bed224c5947417"
MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
NEW_PRIORITY_CEILING_NAMES = (
    "pthread_mutexattr_getprioceiling",
    "pthread_mutexattr_setprioceiling",
)
LINKER_CONTEXT = re.compile(r"^(?:\S*/)?ld: .+: in function [`'][^`']+['']:$")
LINKER_UNDEFINED_REFERENCE = re.compile(
    r"^(?:(?:\S*/)?ld: )?.+: undefined reference to [`']([A-Za-z_][A-Za-z0-9_]*)['']$"
)
COLLECT2_LINK_FAILURE = "collect2: error: ld returned 1 exit status"


class OracleNoProviderAuditError(ValueError):
    """The native oracle inputs cannot establish the no-provider boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OracleNoProviderAuditError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def require_successful_inspection(tool: str, returncode: int, stderr: str) -> None:
    """Reject a failed inspection instead of treating its empty output as absence."""

    require(returncode == 0, f"{tool} failed ({returncode}): {stderr.strip() or 'no diagnostic'}")


def global_or_weak_providers(output: str, names: set[str]) -> dict[str, list[str]]:
    """Return every selected defined POSIX-``nm`` row, including IFUNC/UNIQUE.

    The command supplies ``-g --defined-only --format=posix``. Its selected
    rows therefore have a POSIX name and one-character type field; no finite
    spelling whitelist is safe because GNU extensions such as ``i`` and ``u``
    still name actual providers.
    """

    providers: dict[str, list[str]] = {}
    for line_number, line in enumerate(output.splitlines(), start=1):
        fields = line.split()
        selected_indexes = [index for index, field in enumerate(fields) if field in names]
        if not selected_indexes:
            continue
        require(len(selected_indexes) == 1, f"malformed selected nm row at line {line_number}: {line}")
        name_index = selected_indexes[0]
        prefix_fields = 1 if fields[0].endswith(":") else 0
        require(
            name_index == prefix_fields and len(fields) == prefix_fields + 4,
            f"malformed selected nm row at line {line_number}: {line}",
        )
        binding = fields[name_index + 1]
        require(
            len(binding) == 1 and binding not in {"U", "w", "v"},
            f"selected nm row is not a defined POSIX symbol at line {line_number}: {line}",
        )
        providers.setdefault(fields[name_index], []).append(binding)
    return providers


def dynsym_global_or_weak_providers(output: str, names: set[str]) -> dict[str, list[str]]:
    """Return selected defined GLOBAL/WEAK names from a full ``readelf`` dump."""

    providers: dict[str, list[str]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        binding, section, name = fields[4], fields[6], fields[7]
        if binding in {"GLOBAL", "WEAK"} and section != "UND" and name in names:
            providers.setdefault(name, []).append(binding)
    return providers


def require_no_providers(providers: Mapping[str, Sequence[str]], artifact: str) -> None:
    if providers:
        rendered = ", ".join(
            f"{name} ({'/'.join(bindings)})" for name, bindings in sorted(providers.items())
        )
        raise OracleNoProviderAuditError(f"{artifact} provides declared no-provider symbol(s): {rendered}")


def require_exact_undefined_reference(stderr: str, intended: str) -> None:
    lines = [line for line in stderr.splitlines() if line]
    require(lines, "link failure has no diagnostic")
    names: set[str] = set()
    saw_collect2 = False
    saw_context = False
    for index, line in enumerate(lines):
        undefined = LINKER_UNDEFINED_REFERENCE.fullmatch(line)
        if undefined is not None:
            names.add(undefined.group(1))
            continue
        if LINKER_CONTEXT.fullmatch(line) is not None:
            saw_context = True
            continue
        if line == COLLECT2_LINK_FAILURE:
            require(index == len(lines) - 1, "collect2 link failure is not the final diagnostic")
            saw_collect2 = True
            continue
        raise OracleNoProviderAuditError(f"unexpected linker diagnostic: {line}")
    require(intended in names, f"link failure does not name intended undefined symbol {intended}")
    unexpected = sorted(names - {intended})
    require(
        not unexpected,
        f"link failure includes unrelated undefined symbol(s): {', '.join(unexpected)}",
    )
    require(saw_context, "link failure has no expected ld context diagnostic")
    require(saw_collect2, "link failure has no expected collect2 terminal diagnostic")


def require_exact_undefined_object(output: str, intended: str) -> None:
    names: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        for index, binding in enumerate(fields):
            if binding == "U" and index:
                names.add(fields[index - 1])
    require(names == {intended}, f"compiled object undefined symbols are {sorted(names)}, expected only {intended}")


@dataclass
class Receipt:
    work_dir: Path
    commands: list[dict[str, Any]] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        (self.work_dir / "commands").mkdir()
        (self.work_dir / "inputs").mkdir()
        (self.work_dir / "objects").mkdir()

    def command(
        self,
        identifier: str,
        arguments: Sequence[str],
        *,
        allowed_returncodes: set[int] = {0},
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        require(identifier and re.fullmatch(r"[A-Za-z0-9_.-]+", identifier) is not None, "unsafe command identifier")
        command_dir = self.work_dir / "commands"
        stdout_path = command_dir / f"{identifier}.stdout"
        stderr_path = command_dir / f"{identifier}.stderr"
        try:
            completed = subprocess.run(
                list(arguments),
                cwd=cwd,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key
                    not in {
                        "CPATH",
                        "C_INCLUDE_PATH",
                        "CPLUS_INCLUDE_PATH",
                        "LIBRARY_PATH",
                        "GCC_EXEC_PREFIX",
                        "COMPILER_PATH",
                    }
                },
            )
        except OSError as error:
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(f"{type(error).__name__}: {error}\n", encoding="utf-8")
            self.commands.append(
                {
                    "argv": list(arguments),
                    "cwd": str(cwd) if cwd else None,
                    "id": identifier,
                    "returncode": None,
                    "stderr": str(stderr_path.relative_to(self.work_dir)),
                    "stdout": str(stdout_path.relative_to(self.work_dir)),
                }
            )
            raise OracleNoProviderAuditError(f"could not execute {arguments[0]}: {error}") from error
        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")
        self.commands.append(
            {
                "argv": list(arguments),
                "cwd": str(cwd) if cwd else None,
                "id": identifier,
                "returncode": completed.returncode,
                "stderr": str(stderr_path.relative_to(self.work_dir)),
                "stdout": str(stdout_path.relative_to(self.work_dir)),
            }
        )
        require(
            completed.returncode in allowed_returncodes,
            f"{identifier} returned {completed.returncode}, expected {sorted(allowed_returncodes)}; "
            f"see {stderr_path}",
        )
        return completed

    def write(self) -> None:
        (self.work_dir / "receipt.json").write_text(
            canonical_json(
                {
                    "commands": self.commands,
                    "inputs": self.inputs,
                    "result": self.result,
                    "schema": "crabc.x86_64-header-callable-oracle-no-provider-audit/v1",
                }
            ),
            encoding="utf-8",
        )


def safe_file(path: Path, description: str) -> Path:
    require(path.is_file() and not path.is_symlink(), f"{description} is not a regular file: {path}")
    return path


def checked_no_provider_members(contract_path: Path, inventory_path: Path) -> tuple[list[str], dict[str, set[str]]]:
    try:
        with contract_path.open("rb") as stream:
            contract = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise OracleNoProviderAuditError(f"cannot load callable disposition contract: {error}") from error
    groups = contract.get("deferred_owner_group")
    require(isinstance(groups, list), "callable disposition has no deferred-owner groups")
    selected = [
        group
        for group in groups
        if isinstance(group, Mapping) and group.get("resolution") == NO_PROVIDER_RESOLUTION
    ]
    require(len(selected) == 1, "callable disposition must contain exactly one oracle no-provider group")
    group = selected[0]
    members = group.get("members")
    require(isinstance(members, list) and members, "oracle no-provider group has no members")
    require(all(isinstance(member, str) and member for member in members), "oracle no-provider member is invalid")
    require(members == sorted(members) and len(members) == len(set(members)), "oracle no-provider members drifted")

    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OracleNoProviderAuditError(f"cannot load checked callable inventory: {error}") from error
    require(isinstance(inventory, Mapping), "checked callable inventory is not an object")
    require(inventory.get("schema") == INVENTORY_SCHEMA, "checked callable inventory schema drifted")
    records = inventory.get("callables")
    require(isinstance(records, list), "checked callable inventory has no callable rows")
    headers: dict[str, set[str]] = {member: set() for member in members}
    pinned_references: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            continue
        name = record.get("name")
        if name not in headers:
            continue
        if record.get("classification") != "external" or record.get("declaration_kind") != "function":
            continue
        if record.get("tree") == "candidate":
            declaring_header = record.get("declaring_header")
            require(isinstance(declaring_header, str) and declaring_header, f"inventory declaration header missing for {name}")
            headers[name].add(declaring_header)
        elif record.get("tree") == "reference":
            pinned_references.add(name)
    missing = sorted(name for name, values in headers.items() if not values)
    require(not missing, f"oracle no-provider names are not declared candidate externals: {', '.join(missing)}")
    missing_references = sorted(set(members) - pinned_references)
    require(
        not missing_references,
        "oracle no-provider names are not pinned reference external functions: "
        + ", ".join(missing_references),
    )
    return list(members), headers


def require_native_oracle(receipt: Receipt, compiler: Path, musl_root: Path) -> tuple[Path, Path]:
    require(platform.system() == "Linux", "requires native Linux")
    require(platform.machine() in {"x86_64", "amd64"}, f"refuses non-native execution on {platform.machine()}")
    manifest = safe_file(musl_root / ".crabc-oracle", "pinned musl oracle manifest")
    expected_manifest = "\n".join(
        (
            "format=crabc-pinned-musl-oracle-v1",
            f"version={MUSL_VERSION}",
            f"source_sha256={MUSL_SHA256}",
            f"fallback_revision={MUSL_REVISION}",
            "architecture=x86_64",
            "",
        )
    )
    actual_manifest = manifest.read_text(encoding="utf-8")
    require(actual_manifest == expected_manifest, "pinned musl .crabc-oracle manifest drifted")
    safe_file(compiler, "pinned musl compiler wrapper")
    libc_archive = safe_file(musl_root / "lib" / "libc.a", "pinned musl static libc")
    libc_shared = safe_file(musl_root / "lib" / "libc.so", "pinned musl shared libc")
    receipt.inputs["native_execution"] = {
        "machine": platform.machine(),
        "system": platform.system(),
    }
    receipt.inputs["oracle_manifest"] = {
        "path": str(manifest),
        "sha256": sha256_file(manifest),
        "text": actual_manifest,
    }
    receipt.inputs["compiler"] = {"path": str(compiler), "sha256": sha256_file(compiler)}
    receipt.inputs["libraries"] = {
        "libc.a": {"path": str(libc_archive), "sha256": sha256_file(libc_archive)},
        "libc.so": {"path": str(libc_shared), "sha256": sha256_file(libc_shared)},
    }
    return libc_archive, libc_shared


def capture_header_identities(receipt: Receipt, musl_root: Path, headers: Mapping[str, set[str]]) -> None:
    header_paths = sorted({header for values in headers.values() for header in values})
    identities: dict[str, dict[str, str]] = {}
    for header in header_paths:
        path = safe_file(musl_root / "include" / header, f"pinned musl declaration header {header}")
        identities[header] = {"path": str(path), "sha256": sha256_file(path)}
    receipt.inputs["declaring_headers"] = identities
    receipt.inputs["member_declaration_headers"] = {
        name: sorted(values) for name, values in sorted(headers.items())
    }


def acquire_source_archive(receipt: Receipt, scratch_root: Path, source_url: str) -> Path:
    cache_dir = scratch_root / "source-oracles"
    cache_dir.mkdir(exist_ok=True)
    require(cache_dir.is_dir() and not cache_dir.is_symlink(), "source archive cache is unsafe")
    cached = cache_dir / f"musl-{MUSL_VERSION}.tar.gz"
    require(not cached.is_symlink(), "source archive cache entry is unsafe")
    retained = receipt.work_dir / "inputs" / cached.name
    if cached.is_file() and not cached.is_symlink():
        receipt.command("source-archive-copy", ["cp", "--", str(cached), str(retained)])
    else:
        receipt.command("source-archive-fetch", ["curl", "--fail", "--location", "--retry", "3", "--output", str(retained), source_url])
    actual_digest = sha256_file(retained)
    require(actual_digest == MUSL_SHA256, f"pinned musl source archive digest drifted: {actual_digest}")
    if not cached.exists():
        shutil.copyfile(retained, cached)
        os.chmod(cached, 0o644)
    receipt.inputs["source_archive"] = {
        "path": str(retained.relative_to(receipt.work_dir)),
        "sha256": actual_digest,
        "url": source_url,
    }
    return retained


def extract_and_scan_source(receipt: Receipt, archive: Path, members: Sequence[str]) -> None:
    source_dir = receipt.work_dir / "source"
    source_dir.mkdir()
    receipt.command("source-archive-extract", ["tar", "-xzf", str(archive), "-C", str(source_dir)])
    roots = sorted(path for path in source_dir.iterdir() if path.is_dir() and path.name == f"musl-{MUSL_VERSION}")
    require(len(roots) == 1, "pinned musl source archive root is invalid")
    src = roots[0] / "src"
    require(src.is_dir(), "pinned musl source archive has no src directory")
    receipt.inputs["source_tree"] = {"path": str(src.relative_to(receipt.work_dir))}
    # The priority-ceiling pair is the correction justified by the pinned
    # source absence.  The older cache names deliberately remain in the same
    # no-provider group because their source is conditional on other Linux
    # architectures; their native x86 absence is established by the complete
    # archive/shared artifact audits below.
    source_absent = [member for member in NEW_PRIORITY_CEILING_NAMES if member in members]
    require(
        not source_absent or source_absent == list(NEW_PRIORITY_CEILING_NAMES),
        "oracle no-provider group splits the priority-ceiling declaration pair",
    )
    for member in source_absent:
        result = receipt.command(
            f"source-scan-{member}",
            ["grep", "-R", "-n", "-F", "--", member, str(src)],
            allowed_returncodes={0, 1},
        )
        require(result.returncode == 1, f"pinned musl source src contains {member}")


def compiler_identity(receipt: Receipt, compiler: Path, libc_archive: Path, libc_shared: Path) -> None:
    target = receipt.command("compiler-target", [str(compiler), "-dumpmachine"]).stdout.strip()
    require(re.fullmatch(r"x86_64[^\n]*-musl", target) is not None, f"oracle compiler target drifted: {target}")
    receipt.command("compiler-version", [str(compiler), "--version"])
    # GCC's ``-print-file-name`` bypasses the wrapper's link specs on this
    # Alpine toolchain, so it cannot establish the selected libc path.  The
    # wrapper spelling and its checksummed musl-generated specs do establish
    # that path; ``run_musl_oracle.sh`` additionally compiles and executes the
    # selected dynamic product before this audit is invoked.
    expected_wrapper = 'exec /usr/bin/gcc -specs /opt/musl-1.2.6/lib/musl-gcc.specs "$@"'
    require(expected_wrapper in compiler.read_text(encoding="utf-8").splitlines(), "oracle compiler wrapper drifted")
    specs_manifest = safe_file(libc_archive.parent.parent / ".crabc-musl-gcc-specs.sha256", "pinned musl compiler specs manifest")
    receipt.command("compiler-specs-sha256", ["sha256sum", "-c", str(specs_manifest)])
    receipt.inputs["compiler_specs_manifest"] = {"path": str(specs_manifest), "sha256": sha256_file(specs_manifest)}
    # Retain GCC's diagnostic answers too, while keeping them distinct from
    # the wrapper's selected link path.
    receipt.command("compiler-libc-a-diagnostic", [str(compiler), "-print-file-name=libc.a"])
    receipt.command("compiler-libc-so-diagnostic", [str(compiler), "-print-file-name=libc.so"])
    receipt.inputs["compiler_target"] = target


def audit_symbols(receipt: Receipt, nm: str, readelf: str, libc_archive: Path, libc_shared: Path, members: Sequence[str]) -> None:
    wanted = set(members)
    archive_nm = receipt.command(
        "libc-a-nm-global-defined",
        [nm, "-A", "-g", "--defined-only", "--format=posix", str(libc_archive)],
    )
    require_successful_inspection("nm libc.a", archive_nm.returncode, archive_nm.stderr)
    require_no_providers(global_or_weak_providers(archive_nm.stdout, wanted), "pinned libc.a")

    shared_nm = receipt.command(
        "libc-so-nm-global-defined",
        [nm, "-D", "-g", "--defined-only", "--format=posix", str(libc_shared)],
    )
    require_successful_inspection("nm libc.so", shared_nm.returncode, shared_nm.stderr)
    require_no_providers(global_or_weak_providers(shared_nm.stdout, wanted), "pinned libc.so nm export table")

    dynsym = receipt.command("libc-so-readelf-dynsym", [readelf, "--dyn-syms", "--wide", str(libc_shared)])
    require_successful_inspection("readelf libc.so .dynsym", dynsym.returncode, dynsym.stderr)
    require_no_providers(
        dynsym_global_or_weak_providers(dynsym.stdout, wanted),
        "pinned libc.so .dynsym",
    )


def priority_ceiling_source(symbol: str, language: str) -> str:
    require(symbol in NEW_PRIORITY_CEILING_NAMES, f"unsupported priority-ceiling symbol {symbol}")
    restrict = " restrict" if language == "c11" else ""
    if symbol.endswith("getprioceiling"):
        declaration = (
            f"static int (*const typed_call)(const pthread_mutexattr_t *{restrict}, int *{restrict}) "
            "= pthread_mutexattr_getprioceiling;\n"
        )
        call = "typed_call(&attribute, &ceiling)"
    else:
        declaration = "static int (*const typed_call)(pthread_mutexattr_t *, int) = pthread_mutexattr_setprioceiling;\n"
        call = "typed_call(&attribute, ceiling)"
    main = "int main(void)" if language == "c11" else "int main()"
    return (
        "#include <pthread.h>\n"
        + declaration
        + main
        + " {\n    pthread_mutexattr_t attribute;\n    int ceiling = 0;\n    return "
        + call
        + ";\n}\n"
    )


def audit_priority_ceiling_links(receipt: Receipt, compiler: Path, nm: str, members: Sequence[str]) -> None:
    selected = [name for name in NEW_PRIORITY_CEILING_NAMES if name in members]
    require(
        not selected or selected == list(NEW_PRIORITY_CEILING_NAMES),
        "oracle no-provider group splits the priority-ceiling declaration pair",
    )
    link_records: list[dict[str, Any]] = []
    for symbol in selected:
        for language, extension, flags in (
            ("c11", "c", ["-std=c11"]),
            ("cxx17", "cc", ["-x", "c++", "-std=c++17"]),
        ):
            source = receipt.work_dir / "objects" / f"{symbol}.{extension}"
            object_file = receipt.work_dir / "objects" / f"{symbol}.{language}.o"
            source.write_text(priority_ceiling_source(symbol, language), encoding="utf-8")
            source_hash = sha256_file(source)
            receipt.command(
                f"compile-{symbol}-{language}",
                [str(compiler), *flags, "-fno-builtin", "-fno-pie", "-fno-stack-protector", "-c", str(source), "-o", str(object_file)],
            )
            require(object_file.is_file(), f"installed-oracle-header compile did not write {object_file.name}")
            object_hash = sha256_file(object_file)
            undefined = receipt.command(
                f"object-undefined-{symbol}-{language}",
                [nm, "--undefined-only", "--format=posix", str(object_file)],
            )
            require_exact_undefined_object(undefined.stdout, symbol)
            for mode, flags in (("static", ["-static"]), ("dynamic", [])):
                before_link = sha256_file(object_file)
                require(before_link == object_hash, f"{object_file.name} changed before {mode} link")
                output = receipt.work_dir / "objects" / f"{symbol}.{language}.{mode}"
                link = receipt.command(
                    f"link-{symbol}-{language}-{mode}",
                    [str(compiler), "-no-pie", *flags, str(object_file), "-o", str(output)],
                    allowed_returncodes={1},
                )
                require_exact_undefined_reference(link.stderr, symbol)
                after_link = sha256_file(object_file)
                require(after_link == object_hash, f"{object_file.name} changed during {mode} link")
                link_records.append(
                    {
                        "language": language,
                        "mode": mode,
                        "object": str(object_file.relative_to(receipt.work_dir)),
                        "object_sha256": object_hash,
                        "source": str(source.relative_to(receipt.work_dir)),
                        "source_sha256": source_hash,
                        "symbol": symbol,
                    }
                )
    receipt.result["priority_ceiling_link_witnesses"] = link_records


def audit(arguments: argparse.Namespace, receipt: Receipt) -> None:
    contract = safe_file(arguments.contract, "callable disposition contract")
    inventory = safe_file(arguments.inventory, "checked callable inventory")
    members, headers = checked_no_provider_members(contract, inventory)
    receipt.inputs["contract"] = {"path": str(contract), "sha256": sha256_file(contract)}
    receipt.inputs["inventory"] = {"path": str(inventory), "sha256": sha256_file(inventory)}
    receipt.result["members"] = members

    libc_archive, libc_shared = require_native_oracle(receipt, arguments.compiler, arguments.musl_root)
    capture_header_identities(receipt, arguments.musl_root, headers)
    compiler_identity(receipt, arguments.compiler, libc_archive, libc_shared)
    archive = acquire_source_archive(receipt, arguments.scratch_root, arguments.source_url)
    extract_and_scan_source(receipt, archive, members)
    audit_symbols(receipt, arguments.nm, arguments.readelf, libc_archive, libc_shared, members)
    audit_priority_ceiling_links(receipt, arguments.compiler, arguments.nm, members)
    receipt.result.update(
        {
            "family_or_header_closure": False,
            "provider_archive_closure": False,
            "runtime_behavior_closed": False,
            "status": "structural-oracle-declared-no-provider",
        }
    )


def native_work_dir(work_root: Path, scratch_root: Path) -> Path:
    work_root = work_root.resolve()
    scratch_root = scratch_root.resolve()
    expected_prefix = scratch_root / "tmp"
    require(work_root == expected_prefix or work_root.is_relative_to(expected_prefix), "audit work root must be below native .work/x86_64/tmp")
    require(scratch_root == ROOT / ".work" / "x86_64", "audit scratch root must be this checkout's .work/x86_64")
    work_root.mkdir(parents=True, exist_ok=True)
    require(work_root.is_dir() and not work_root.is_symlink(), "audit work root is unsafe")
    created = Path(tempfile.mkdtemp(prefix="header-callable-oracle-no-provider.", dir=work_root))
    # The dispatcher container writes as root but its retained evidence must
    # remain reviewable from the checkout-owning group after it exits.
    os.chmod(created, 0o2770)
    return created


def parse_args(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=ROOT / "compat/x86_64/header_callable_disposition.toml")
    parser.add_argument("--inventory", type=Path, default=ROOT / "compat/x86_64/header_callable_inventory.json")
    parser.add_argument("--musl-root", type=Path, default=MUSL_ROOT)
    parser.add_argument("--compiler", type=Path, default=ORACLE_CC)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--source-url", default=f"https://musl.libc.org/releases/musl-{MUSL_VERSION}.tar.gz")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_args(arguments)
    work_dir = native_work_dir(parsed.work_root, parsed.scratch_root)
    receipt = Receipt(work_dir)
    try:
        audit(parsed, receipt)
    except Exception as error:
        receipt.result.update({"error": str(error), "status": "failed"})
        receipt.write()
        print(f"ERROR: x86 header callable oracle no-provider audit: {error}", file=sys.stderr)
        print(f"retained receipts: {work_dir}", file=sys.stderr)
        return 1
    receipt.write()
    print(f"x86 header callable oracle no-provider audit: PASS (structural no-provider; receipts: {work_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
