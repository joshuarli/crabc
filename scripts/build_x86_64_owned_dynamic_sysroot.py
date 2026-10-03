#!/usr/bin/env python3
"""Produce the native shared runtime, without ambient target inputs.

Tool attestation, header provenance and Cargo archive membership classification
are shared with the static producer. Final shared linkage is separate: every
member is explicit. The default retains only the accepted pinned C mimalloc
implementation; explicit native shadow selection excludes that exact member.
Neither selection is dynamic-product campaign completion.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import re
import tomllib

sys.dont_write_bytecode = True
# Qualification cases run with PYTHONSAFEPATH=1, which omits this script's
# directory from sys.path; name it so sibling imports still resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_x86_64_owned_sysroot as common  # noqa: E402

ROOT = common.ROOT
FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
LOADER_PROVENANCE_SCHEMA = "crabc.x86_64-owned-loader-provenance/v1"
LOADER_FEATURE = "x86_64-owned-dynamic-runtime"
LOADER_ARTIFACT = "lib/ld-crabc-x86_64.so.1"
LOADER_DEPENDENCY_ARTIFACT = "libldso.so"
# This is the checked byte-for-byte musl 1.2.6 `dynamic.list` input.  Musl
# configure adds it only to libc's shared link: public data remains available
# for copy relocations, and the listed allocation entrypoints deliberately
# remain interposable.  It is not a substitute for the source's explicit
# public versus hidden internal calls, and it must never be applied to the
# loader, application DSOs, or static archives.
SHARED_LIBC_DYNAMIC_LIST = ROOT / "libc/src/c_abi/x86_64/owned_dynamic.list"
# Musl's internal `src/include/errno.h` declares `___errno_location` hidden
# before `src/errno/__errno_location.c` forms its weak alias. GNU ld reduces
# that alias to LOCAL DEFAULT in musl's shared symbol table. The selected LLD
# retains HIDDEN instead, so this exact shared-link-only input localizes the
# one Rust/C allocator seam after objects have resolved it. It is distinct
# from musl's public dynamic-list and from the fixed C mimalloc list below.
SHARED_LIBC_ERRNO_PRIVATE_ALIASES = ROOT / "libc/src/c_abi/x86_64/owned_errno_private_aliases.list"
# This is an exact, reviewed local-symbol contract for the one bundled C
# allocator member selected by `libmimalloc-sys` 0.1.49. It names its 172
# upstream `mimalloc.h` declarations and 252 non-header implementation names;
# it is not a prefix rule and does not select a different object or backend.
SHARED_LIBC_MIMALLOC_HIDDEN_LIST = ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list"
# Layout-only input for the same shared link: the functions startup and the
# native C performance rows execute are placed together so a process maps
# few 64 KiB fault-around windows of libc text. See the file's header.
SHARED_LIBC_SYMBOL_ORDER = ROOT / "libc/src/c_abi/x86_64/owned_dynamic_hot.order"
# Both runtime images discard their unused unwind tables, as musl's do.
# Import-time root; provenance re-roots these through ROOT so a relocated
# checkout records them like every other configuration input.
_IMPORT_ROOT = ROOT
RUNTIME_DISCARD_UNWIND_SCRIPT = ROOT / "libc/src/c_abi/x86_64/owned_discard_unwind.ld"
# The interpreter packs small mutable statics into the last .data page.
LOADER_BSS_LAYOUT_SCRIPT = ROOT / "ldso/x86_64-owned-bss-layout.ld"
COMPILER_HELPER_CONTRACT = ROOT / "builtins/x86_64-helper-contract.toml"
SHARED_LIBC_COMPILER_HELPER_ARCHIVE = "libcrabc-builtins.a"
SHARED_LIBC_COMPILER_HELPER_MEMBER = "crabc-builtins.o"
SHARED_LIBC_COMPILER_HELPER_POLICY = {
    "artifact": "candidate-shared",
    "linker_option": "--exclude-libs=libcrabc-builtins.a",
    "type": "FUNC",
    "binding": "LOCAL",
    "visibility": "DEFAULT",
    "dynsym": False,
}
MUSL_1_2_6_DYNAMIC_LIST_SHA256 = "264ae3bf630a7f6d894a51f91f9acae45b89a5f639537353d03af1a04e9da0f9"
ERRNO_PRIVATE_ALIAS_LIST_SHA256 = "2e69ec5346002fa183b51dbbbef2f24744bd89093b5cfac6329337c1b3d240dd"
ERRNO_PRIVATE_ALIAS_MEMBERS = ("___errno_location",)
MIMALLOC_V3_HIDDEN_LIST_SHA256 = "cd537f6579018bbba79d831ee148a7b07f51a0f3bda538a27970724751d78873"
MIMALLOC_V3_HIDDEN_LIST_COUNT = 424
MUSL_1_2_6_DYNAMIC_LIST_MEMBERS = (
    "environ", "__environ", "stdin", "stdout", "stderr",
    "malloc", "calloc", "realloc", "free", "memalign", "posix_memalign",
    "aligned_alloc", "malloc_usable_size",
    "timezone", "daylight", "tzname", "__timezone", "__daylight", "__tzname",
    "signgam", "__signgam", "optarg", "optind", "opterr", "optopt", "optreset",
    "__optreset", "getdate_err", "h_errno", "program_invocation_name",
    "program_invocation_short_name", "__progname", "__progname_full", "__stack_chk_guard",
)
MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS = (
    "malloc", "calloc", "realloc", "free", "memalign", "posix_memalign",
    "aligned_alloc", "malloc_usable_size",
)
MUSL_1_2_6_DYNAMIC_LIST_DATA_SYMBOLS = tuple(
    member for member in MUSL_1_2_6_DYNAMIC_LIST_MEMBERS
    if member not in MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS
)
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import crabc_cc_owned_dynamic as installed_driver
import owned_static_sysroot_package as shared_package
import owned_dynamic_elf as elf_inspection
import owned_dynamic_qualification as qualification
import native_static_source_runtime_closure as source_runtime


def audit_shared_elf(path: Path) -> dict[str, str]:
    """Require a self-contained, position-independent abort-only runtime ELF."""
    dynamic = common.run(["/usr/bin/readelf", "-dW", str(path)]).decode()
    relocations = common.run(["/usr/bin/readelf", "-rW", str(path)]).decode()
    segments = common.run(["/usr/bin/readelf", "-lW", str(path)]).decode()
    if "(NEEDED)" in dynamic or "TEXTREL" in dynamic or "INTERP" in segments:
        raise common.BuildError(f"owned shared ELF has a foreign dependency/interpreter or text relocation: {path}")
    if re.search(r"\bR_X86_64_32S?\b", relocations):
        raise common.BuildError(f"owned shared ELF retains an absolute 32-bit relocation: {path}")
    if "GNU_RELRO" not in segments or not re.search(r"GNU_STACK.* RW +", segments):
        raise common.BuildError(f"owned shared ELF lacks RELRO or non-executable stack: {path}")
    # Libc and the interpreter never own language exception machinery. Inspect
    # local definitions as well as dynamic exports and unresolved imports, so
    # symbol visibility cannot conceal a personality stub or runtime fallback.
    symbols = common.run(["/usr/bin/readelf", "-sW", str(path)]).decode()
    forbidden = []
    for line in symbols.splitlines():
        fields = line.split()
        if (len(fields) >= 8 and fields[3] not in {"FILE", "SECTION"}
                and source_runtime.FORBIDDEN_FINAL_SYMBOL.search(fields[7])):
            forbidden.append(fields[7])
    if forbidden:
        raise common.BuildError(f"owned abort runtime contains language exception symbols: {sorted(set(forbidden))}: {path}")
    # Unwinders reach an object's frames only through PT_GNU_EH_FRAME; this is
    # the same rule the installed driver applies to every application link.
    try:
        elf_inspection.require_unwind_table_header(elf_inspection.unwind_table_facts(path))
    except elf_inspection.InspectionError as error:
        raise common.BuildError(f"owned shared ELF unwind tables are unreachable: {path}: {error}") from error
    return {"dynamic": dynamic, "relocations": relocations, "segments": segments}


def _source_file_identity(path: Path, description: str) -> dict[str, object]:
    """Record one physical source input by checkout-relative identity."""

    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise common.BuildError(f"{description} is missing or unsafe: {path}") from error
    source_root = ROOT.resolve()
    if (not stat.S_ISREG(details.st_mode) or path.is_symlink() or resolved != path
            or not resolved.is_relative_to(source_root)):
        raise common.BuildError(f"{description} is not a physical checkout file: {path}")
    return {
        "path": resolved.relative_to(source_root).as_posix(),
        "sha256": common.sha256_file(resolved),
        "mode": stat.S_IMODE(details.st_mode),
    }


def _normalized_loader_argument(argument: str, stage: Path) -> str:
    """Replace build-local prefixes without changing an arbitrary argument."""

    for option in ("--dynamic-list=", "--version-script=", "--symbol-ordering-file="):
        if argument.startswith(option):
            return option + _normalized_loader_argument(argument.removeprefix(option), stage)
    for physical, replacement in ((stage.resolve(), "$BUILD"), (ROOT.resolve(), "$SOURCE")):
        spelling = str(physical)
        if argument == spelling:
            return replacement
        if argument.startswith(spelling + os.sep):
            return replacement + argument[len(spelling):]
    return argument


def shared_libc_dynamic_list() -> dict[str, object]:
    """Read only the pinned musl shared-libc interposition exception list.

    `--dynamic-list` has a deliberately narrow meaning here.  The ordinary
    exported functions bind locally within `libc.so`; listed data remains
    interposable for copy relocations, while the allocation family remains
    interposable as musl's explicit function exception.  The input is exact so
    a future change cannot silently widen either category.
    """

    identity = _source_file_identity(SHARED_LIBC_DYNAMIC_LIST, "native libc shared dynamic-list")
    if identity["sha256"] != MUSL_1_2_6_DYNAMIC_LIST_SHA256:
        raise common.BuildError("native libc shared dynamic-list differs from pinned musl 1.2.6")
    try:
        text = SHARED_LIBC_DYNAMIC_LIST.read_text(encoding="utf-8")
    except OSError as error:
        raise common.BuildError("native libc shared dynamic-list cannot be read") from error
    if re.fullmatch(r"\s*\{\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*;\s*)*\}\s*;\s*", text) is None:
        raise common.BuildError("native libc shared dynamic-list has unsupported syntax")
    members = tuple(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*;", text))
    if members != MUSL_1_2_6_DYNAMIC_LIST_MEMBERS:
        raise common.BuildError("native libc shared dynamic-list member/order contract differs")
    return {
        "source": identity,
        "data_symbols": list(MUSL_1_2_6_DYNAMIC_LIST_DATA_SYMBOLS),
        "allocation_entrypoints": list(MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS),
    }


def shared_libc_mimalloc_hidden_exports(stage: Path) -> dict[str, object]:
    """Materialize the exact local-only list for this one shared libc link.

    The selected `libmimalloc-sys` 0.1.49 member retains all of these global
    definitions in `libc.a`.  Its upstream header and implementation spellings
    are not installed crabc headers, and this version script changes only their
    physical visibility in `libc.so`.  Keep the source list exact: a glob or
    prefix would silently capture a later contract.
    """

    identity = _source_file_identity(
        SHARED_LIBC_MIMALLOC_HIDDEN_LIST, "native libc mimalloc hidden-export list"
    )
    if identity["sha256"] != MIMALLOC_V3_HIDDEN_LIST_SHA256:
        raise common.BuildError("native libc mimalloc hidden-export list differs from its reviewed contract")
    try:
        members = tuple(SHARED_LIBC_MIMALLOC_HIDDEN_LIST.read_text(encoding="utf-8").splitlines())
    except OSError as error:
        raise common.BuildError("native libc mimalloc hidden-export list cannot be read") from error
    if (len(members) != MIMALLOC_V3_HIDDEN_LIST_COUNT or not members
            or any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", member) is None for member in members)
            or members != tuple(sorted(set(members)))):
        raise common.BuildError("native libc mimalloc hidden-export list member/order contract differs")
    script = stage / "libc-mimalloc-hidden.exports"
    script.write_text("{\n  local:\n" + "".join(f"    {member};\n" for member in members) + "};\n",
                      encoding="utf-8")
    script.chmod(0o600)
    return {
        "source": identity,
        "member_count": len(members),
        "members": list(members),
        "linker_script_sha256": common.sha256_file(script),
        "linker_policy": "exact-local-symbols",
    }


def shared_libc_compiler_helper_archive_policy() -> dict[str, object]:
    """Bind libc.so's private copy to the archive's exact producer contract.

    The installed static-builtins and dynamic-builtins roles remain ordinary
    GLOBAL DEFAULT providers. This applies only to the same archive member
    included while linking libc.so for internal compiler-generated calls. The
    archive builder rejects any extra external definition, so LLD's exact
    archive-name exclusion cannot capture another runtime owner as a wildcard.
    """

    identity = _source_file_identity(COMPILER_HELPER_CONTRACT, "native compiler-helper contract")
    try:
        value = tomllib.loads(COMPILER_HELPER_CONTRACT.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise common.BuildError("native compiler-helper contract cannot be read") from error
    if (type(value) is not dict
            or value.get("archive") != {"name": SHARED_LIBC_COMPILER_HELPER_ARCHIVE,
                                         "member": SHARED_LIBC_COMPILER_HELPER_MEMBER,
                                         "placements": ["static-builtins", "dynamic-builtins"]}
            or type(value.get("shared_libc")) is not dict
            or type(value["shared_libc"].get("dynsym")) is not bool
            or value.get("shared_libc") != SHARED_LIBC_COMPILER_HELPER_POLICY):
        raise common.BuildError("native compiler-helper shared-libc placement differs from its producer contract")
    return {
        "source": identity,
        "archive": SHARED_LIBC_COMPILER_HELPER_ARCHIVE,
        "member": SHARED_LIBC_COMPILER_HELPER_MEMBER,
        **SHARED_LIBC_COMPILER_HELPER_POLICY,
    }


def shared_libc_errno_private_aliases(stage: Path) -> dict[str, object]:
    """Materialize the exact LLD localization input for the errno weak alias.

    The archive keeps musl's weak hidden alias so the C allocator object can
    resolve it. The shared link must first resolve that same object edge, then
    reduce only this alias to LOCAL DEFAULT. Do not put it in musl's public
    dynamic-list or the mimalloc version script: those lists have separate
    provenance and interposition contracts.
    """

    identity = _source_file_identity(
        SHARED_LIBC_ERRNO_PRIVATE_ALIASES, "native libc errno private-alias list"
    )
    if identity["sha256"] != ERRNO_PRIVATE_ALIAS_LIST_SHA256:
        raise common.BuildError("native libc errno private-alias list differs from its reviewed contract")
    try:
        members = tuple(SHARED_LIBC_ERRNO_PRIVATE_ALIASES.read_text(encoding="utf-8").splitlines())
    except OSError as error:
        raise common.BuildError("native libc errno private-alias list cannot be read") from error
    if members != ERRNO_PRIVATE_ALIAS_MEMBERS:
        raise common.BuildError("native libc errno private-alias roster differs")
    script = stage / "libc-errno-private.exports"
    script.write_text("{\n  local:\n" + "".join(f"    {member};\n" for member in members) + "};\n",
                      encoding="utf-8")
    script.chmod(0o600)
    return {
        "source": identity,
        "member_count": len(members),
        "members": list(members),
        "linker_script_sha256": common.sha256_file(script),
        "linker_policy": "exact-local-symbols",
    }


def shared_libc_symbol_order(nm: str, inputs: list[Path], stage: Path) -> dict[str, object]:
    """Resolve the hot-text order to this link's actual symbol spellings.

    Entries name C symbols or hash-free demangled Rust paths, so crate
    disambiguators may change without editing the list. An entry that no
    longer names a defined symbol costs only layout; it is recorded, not fatal.
    """

    identity = _source_file_identity(SHARED_LIBC_SYMBOL_ORDER, "native libc hot text order")
    try:
        text = SHARED_LIBC_SYMBOL_ORDER.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise common.BuildError("native libc hot text order cannot be read") from error
    entries = [line for line in text.splitlines() if line and not line.startswith("#")]
    if len(set(entries)) != len(entries) or any(line != line.strip() for line in entries):
        raise common.BuildError("native libc hot text order repeats or pads an entry")
    spellings: dict[str, list[str]] = {}
    for path in inputs:
        listing = [common.run([nm, "--defined-only", *demangle, "--format=just-symbols", str(path)])
                   .decode().splitlines() for demangle in ([], ["--demangle"])]
        if len(listing[0]) != len(listing[1]):
            raise common.BuildError(f"demangled symbol listing does not align: {path}")
        for raw, readable in zip(*listing):
            if raw and not raw.endswith(":") and raw not in spellings.setdefault(readable, []):
                spellings[readable].append(raw)
    resolved = [raw for entry in entries for raw in spellings.get(entry, [])]
    unresolved = [entry for entry in entries if entry not in spellings]
    script = stage / "libc-hot.order"
    script.write_text("".join(f"{name}\n" for name in resolved), encoding="utf-8")
    script.chmod(0o600)
    return {
        "source": identity,
        "entry_count": len(entries),
        "resolved_symbol_count": len(resolved),
        "unresolved_entries": unresolved,
        "ordering_file_sha256": common.sha256_file(script),
    }


HOT_RODATA_OUTPUT_SECTION = ".rodata.crabc.hot"
_ELF_SECTION_ROW = re.compile(r"\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)")
_LINKER_SCRIPT_NAME = re.compile(r"[A-Za-z0-9_.$]+")


def shared_libc_hot_rodata(objects: list[Path], stage: Path) -> dict[str, object]:
    """Place the read-only data of the ordered hot functions beside the headers.

    Every process touches libc.so's dynamic symbol, hash and string tables at
    load. The constants its hot text reads were scattered over the following
    148 KiB of .rodata, so their fault-around windows kept most of it
    resident. This follows each hot function's relocations (through the data
    sections it points at, up to three levels) to the .rodata input sections
    they reach and emits an INSERT script that gathers exactly those inputs
    into one output section in front of .rodata. It changes only layout.
    """

    hot = set((stage / "libc-hot.order").read_text(encoding="utf-8").split())
    chosen: dict[str, int] = {}
    for path in objects:
        sections: dict[int, tuple[str, int]] = {}
        for line in common.run(["/usr/bin/readelf", "-SW", str(path)]).decode().splitlines():
            match = _ELF_SECTION_ROW.match(line)
            if match:
                sections[int(match.group(1))] = (match.group(2), int(match.group(3), 16))
        sizes = dict(sections.values())
        symbol_section: dict[str, str] = {}
        roots: set[str] = set()
        for line in common.run(["/usr/bin/readelf", "-sW", str(path)]).decode().splitlines():
            fields = line.split()
            if len(fields) >= 8 and fields[6].isdigit() and int(fields[6]) in sections:
                section = sections[int(fields[6])][0]
                symbol_section.setdefault(fields[7], section)
                if fields[3] == "FUNC" and fields[7] in hot:
                    roots.add(section)
        references: dict[str, list[str]] = {}
        current = None
        for line in common.run(["/usr/bin/readelf", "-rW", str(path)]).decode().splitlines():
            header = re.match(r"Relocation section '\.rela([^']+)'", line)
            if header:
                current = header.group(1)
                continue
            fields = line.split()
            if current is not None and len(fields) >= 5 and fields[2].startswith("R_X86_64_"):
                target = fields[4] if fields[4] in sizes else symbol_section.get(fields[4])
                if target:
                    references.setdefault(current, []).append(target)
        frontier, seen = sorted(roots), set(roots)
        for _ in range(3):
            following = []
            for section in frontier:
                for target in references.get(section, []):
                    if target in seen:
                        continue
                    seen.add(target)
                    if target.startswith(".rodata") and _LINKER_SCRIPT_NAME.fullmatch(target):
                        chosen.setdefault(target, sizes.get(target, 0))
                        following.append(target)
                    elif target.startswith((".data", ".tdata")):
                        following.append(target)
            frontier = following
    script = stage / "libc-hot-rodata.ld"
    script.write_text(f"SECTIONS {{ {HOT_RODATA_OUTPUT_SECTION} : {{\n"
                      + "".join(f"  *({name})\n" for name in chosen)
                      + "} } INSERT BEFORE .rodata;\n", encoding="utf-8")
    script.chmod(0o600)
    return {
        "input_section_count": len(chosen),
        "input_section_bytes": sum(chosen.values()),
        "linker_script_sha256": common.sha256_file(script),
    }


def shared_libc_link_command(
    lld: Path,
    dynamic_list: Path,
    mimalloc_hidden_exports: Path | None,
    errno_private_aliases: Path,
    symbol_order: Path,
    hot_rodata: Path,
    objects: Path,
    selected: tuple[str, ...],
    builtins: Path,
    library: Path,
) -> list[str]:
    """Return the one musl-shaped shared-libc link, with no global policy leak."""

    if builtins.name != SHARED_LIBC_COMPILER_HELPER_ARCHIVE:
        raise common.BuildError("shared libc must consume the exact compiler-helper archive name")

    return [
        str(lld), "-shared", "--hash-style=sysv", "--eh-frame-hdr", "-soname", "libc.so",
        f"--dynamic-list={dynamic_list}",
        *([f"--version-script={mimalloc_hidden_exports}"] if mimalloc_hidden_exports is not None else []),
        f"--version-script={errno_private_aliases}",
        "--exclude-libs=" + SHARED_LIBC_COMPILER_HELPER_ARCHIVE,
        "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
        # Packed DT_RELR relative relocations: 849 RELA records (21 KiB the
        # loader reads at every start) become a 264-byte bitmap stream.
        "-z", "pack-relative-relocs",
        f"--symbol-ordering-file={symbol_order}", "--no-warn-symbol-ordering",
        *(str(objects / item) for item in selected),
        # The shared libc owns the complete private helper member even when
        # its selected allocator emits no helper imports. Force only this
        # archive's extraction; subsequent inputs retain ordinary lazy policy.
        "--whole-archive", str(builtins), "--no-whole-archive",
        str(RUNTIME_DISCARD_UNWIND_SCRIPT), str(hot_rodata),
        "-o", str(library / "libc.so"),
    ]


def loader_dependency_provenance(dependencies: Path, artifact: Path, *, object_dependencies: bool = False) -> list[dict[str, object]]:
    """Translate Cargo's one compiler dep-info rule into selected source inputs.

    Cargo emits this file beside the final cdylib.  It is the compiler's
    actual source closure for this artifact, rather than a guessed walk of
    ``ldso/src`` or a collection of source markers.
    """

    try:
        details = dependencies.lstat()
        text = dependencies.read_text(encoding="utf-8")
    except OSError as error:
        raise common.BuildError(f"loader compiler dependency trace is missing: {dependencies}") from error
    if not stat.S_ISREG(details.st_mode) or dependencies.is_symlink():
        raise common.BuildError("loader compiler dependency trace is not a regular file")
    lines = [line for line in text.replace("\\\n", " ").splitlines() if line.strip()]
    if object_dependencies:
        rules = []
        for line in lines:
            target, separator, sources = line.partition(":")
            if not separator or ":" in sources:
                raise common.BuildError("loader object dependency trace has an invalid rule")
            rules.append((shlex.split(target), shlex.split(sources), line))
        primary = [rule for rule in rules if rule[0] == [str(artifact)]]
        if len(primary) != 1 or not primary[0][1]:
            raise common.BuildError("loader object dependency trace does not bind its object")
        for targets, sources, line in rules:
            if line == primary[0][2]:
                continue
            if targets == [str(dependencies)] and sources == primary[0][1]:
                continue
            if len(targets) == 1 and targets[0] in primary[0][1] and not sources:
                continue
            raise common.BuildError("loader object dependency trace has an unrelated rule")
        lines = [primary[0][2]]
    if len(lines) != 1:
        raise common.BuildError("loader compiler dependency trace must contain one rule")
    target, separator, inputs = lines[0].partition(":")
    if not separator or ":" in inputs:
        raise common.BuildError("loader compiler dependency trace has an invalid rule")
    try:
        targets = shlex.split(target)
        sources = shlex.split(inputs)
    except ValueError as error:
        raise common.BuildError("loader compiler dependency trace cannot be parsed") from error
    if len(targets) != 1 or not sources:
        raise common.BuildError("loader compiler dependency trace has an incomplete rule")
    target_path = Path(targets[0])
    try:
        target_details = target_path.lstat()
        resolved_target = target_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise common.BuildError("loader compiler dependency target is missing or unsafe") from error
    if (not target_path.is_absolute() or not stat.S_ISREG(target_details.st_mode)
            or target_path.is_symlink() or resolved_target != target_path):
        raise common.BuildError("loader compiler dependency target is not a physical artifact")
    try:
        expected_target = artifact.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise common.BuildError(f"loader artifact is missing or unsafe: {artifact}") from error
    if resolved_target != expected_target:
        raise common.BuildError("loader compiler dependency target does not bind the installed artifact")

    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for spelling in sources:
        path = Path(spelling)
        if not path.is_absolute():
            raise common.BuildError("loader compiler dependency source is not absolute")
        record = _source_file_identity(path, "loader compiler dependency source")
        name = record["path"]
        if not isinstance(name, str) or not name.startswith("ldso/"):
            raise common.BuildError("loader compiler dependency source is outside ldso")
        if name in seen:
            raise common.BuildError("loader compiler dependency trace has duplicate sources")
        seen.add(name)
        records.append(record)
    records.sort(key=lambda record: str(record["path"]))
    required = {"ldso/src/lib.rs"} if object_dependencies else {"ldso/build.rs", "ldso/src/lib.rs"}
    if not required <= seen:
        raise common.BuildError("loader compiler dependency trace lacks build.rs or lib.rs")
    return records


def loader_provenance(
    stage: Path,
    command: list[str],
    rustflags: str,
    compiler_artifact: Path,
    installed_artifact: Path,
) -> dict[str, object]:
    """Bind the installed loader to Cargo's selected source closure and config."""

    dependencies = stage / "loader" / common.TARGET / "release" / "libldso.d"
    expected_dependency_artifact = dependencies.with_name(LOADER_DEPENDENCY_ARTIFACT)
    if compiler_artifact != expected_dependency_artifact:
        raise common.BuildError("loader artifact does not have the expected Cargo dependency location")
    try:
        compiler_details = compiler_artifact.lstat()
        installed_details = installed_artifact.lstat()
    except OSError as error:
        raise common.BuildError("loader compiler or installed artifact is missing") from error
    if (not stat.S_ISREG(compiler_details.st_mode) or compiler_artifact.is_symlink()
            or not stat.S_ISREG(installed_details.st_mode) or installed_artifact.is_symlink()
            or common.sha256_file(compiler_artifact) != common.sha256_file(installed_artifact)):
        raise common.BuildError("installed loader differs from its compiler artifact")
    configuration = [
        _source_file_identity(ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py", "loader producer"),
        _source_file_identity(ROOT / "scripts/build_x86_64_owned_sysroot.py", "shared producer configuration"),
        _source_file_identity(ROOT / "Cargo.toml", "workspace Cargo configuration"),
        _source_file_identity(ROOT / "Cargo.lock", "workspace Cargo lock"),
        _source_file_identity(ROOT / "rust-toolchain.toml", "pinned Rust toolchain configuration"),
        _source_file_identity(ROOT / ".cargo/config.toml", "workspace Cargo configuration"),
        _source_file_identity(ROOT / "ldso/Cargo.toml", "loader Cargo configuration"),
        _source_file_identity(ROOT / RUNTIME_DISCARD_UNWIND_SCRIPT.relative_to(_IMPORT_ROOT), "runtime unwind-table discard script"),
        _source_file_identity(ROOT / LOADER_BSS_LAYOUT_SCRIPT.relative_to(_IMPORT_ROOT), "loader .bss layout script"),
    ]
    installed = {
        "path": LOADER_ARTIFACT,
        "sha256": common.sha256_file(installed_artifact),
        "mode": stat.S_IMODE(installed_details.st_mode),
    }
    return {
        "schema": LOADER_PROVENANCE_SCHEMA,
        "target": common.TARGET,
        "artifact": installed,
        "cargo": {
            "argv": [_normalized_loader_argument(argument, stage) for argument in command],
            "rustflags": rustflags,
        },
        "compiler_dependencies": loader_dependency_provenance(dependencies, compiler_artifact),
        "configuration": configuration,
    }


ALLOCATOR_BACKENDS = common.ALLOCATOR_BACKENDS


def select_allocator_members(members, allocator_member: str | None, allocator_backend: str):
    """Classify every Cargo member, then exclude the attested C shadow input.

    The native Rust code is in libc's fat-LTO Rust object. Its producer rejects
    any C dependency archive before this strict Rust-only roster is selected.
    Retained legacy archive inputs still require exact member classification.
    """
    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise common.BuildError("unknown dynamic allocator backend")
    if allocator_backend == common.EVIDENCE_ALLOCATOR_BACKEND:
        allocator_backend = "accepted-c"
    classified_allocator = (None if allocator_backend == "native-shadow"
                            and allocator_member not in members else allocator_member)
    selected, excluded = common.classify_libc_members(members, allocator_member=classified_allocator)
    if allocator_backend == "native-shadow":
        selected = tuple(member for member in selected if member != allocator_member)
        excluded = tuple(member for member in members if member not in selected)
    return selected, excluded


def validate_native_allocator_symbols(definitions, imports, loader_symbols) -> None:
    """No selected C allocator implementation or loader/libc heap crossing."""
    c_symbols = sorted(symbol for symbol in definitions | imports
                       if symbol.startswith(("mi_", "_mi_")))
    allocator_edges = {"malloc", "calloc", "realloc", "reallocarray", "free",
                       "aligned_alloc", "memalign", "posix_memalign", "malloc_usable_size",
                       "__libc_malloc", "__libc_calloc", "__libc_realloc", "__libc_free"}
    if c_symbols or loader_symbols & allocator_edges:
        raise common.BuildError(f"native allocator ownership violated: C={c_symbols}, loader={sorted(loader_symbols & allocator_edges)}")


def elf_symbols(nm: str, artifact: Path, selector: str) -> set[str]:
    # The installed loader can be stripped of its ordinary symbol table.
    # Inspect dynamic symbols too, while retaining private libc fini entries.
    return {line.split()[-1]
            for table in ([], ["--dynamic"])
            for line in common.run([nm, *table, selector, str(artifact)]).decode().splitlines()
            if len(line.split()) >= 2 and not line.endswith(":")}


def build(output: Path, *, allocator_backend: str = common.DEFAULT_ALLOCATOR_BACKEND, lifecycle_test_audit: bool = False, profile: str = "release") -> None:
    common.assert_native_target()
    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise common.BuildError("unknown dynamic allocator backend")
    source_before_build = qualification.source_digest()
    output = common.validate_output_path(output)
    if not output.is_relative_to(ROOT / ".work"):
        raise common.BuildError("dynamic output must remain below checkout .work")
    if output.exists() or output.is_symlink():
        raise common.BuildError("dynamic output already exists; choose a fresh owned output")
    stage = output.parent / (output.name + ".build")
    if stage.exists() or stage.is_symlink():
        raise common.BuildError("dynamic build state already exists; choose a fresh owned output")
    stage.mkdir(parents=True, mode=0o700)
    staged_output = stage / "installed"
    build_staged_payload(staged_output, stage, allocator_backend=allocator_backend, lifecycle_test_audit=lifecycle_test_audit, profile=profile)
    if qualification.source_digest() != source_before_build:
        raise common.BuildError("source changed during dynamic product build")
    try:
        installed_driver.validate(staged_output)
        shared_package.publish_noreplace(staged_output, output, "dynamic sysroot output")
    except (installed_driver.shared.DriverError, shared_package.PackageError) as error:
        raise common.BuildError(str(error)) from error


def build_staged_payload(output: Path, stage: Path, *, allocator_backend: str = common.DEFAULT_ALLOCATOR_BACKEND, lifecycle_test_audit: bool = False, profile: str = "release") -> None:
    """Build the complete candidate privately; only build() may publish it.

    Failure retains diagnostic/build state under the dedicated .build owner,
    never a partially populated public output. The final manifest must pass
    the installed driver's exact validation before atomic no-replace rename.
    """
    if profile == "debug":
        build_debug_payload(output, stage, allocator_backend=allocator_backend, lifecycle_test_audit=lifecycle_test_audit)
        return
    if profile != "release":
        raise common.BuildError("unknown owned runtime build profile")
    recorded_backend = allocator_backend
    allocator_backend = common.backend_selection(allocator_backend, lifecycle_test_audit)
    environment = common.deterministic_environment()
    environment["CARGO_BUILD_JOBS"] = "2"
    tools = common.resolve_pinned_producer_tools()
    rustup = tools["rustup"]["path"]
    ar = common.producer_tool_path(tools, "llvm-ar")
    nm = common.producer_tool_path(tools, "llvm-nm")
    objdump = common.producer_tool_path(tools, "llvm-objdump")
    rust_sysroot = common.pinned_rustc_sysroot(Path(rustup))
    lld = rust_sysroot / "lib/rustlib" / common.TARGET / "bin/gcc-ld/ld.lld"
    shared_dynamic_list = shared_libc_dynamic_list()
    evidence_c = allocator_backend == common.EVIDENCE_ALLOCATOR_BACKEND
    accepted_c = allocator_backend in common.C_ALLOCATOR_BACKENDS
    shared_mimalloc_hidden_exports = (shared_libc_mimalloc_hidden_exports(stage)
        if accepted_c else {"status": "not-selected-native-shadow"})
    shared_compiler_helper_policy = shared_libc_compiler_helper_archive_policy()
    shared_errno_private_aliases = shared_libc_errno_private_aliases(stage)
    run = common.run
    dependency_file = stage / "allocator.d"
    c_flags = ["-nostdinc", "-isystem", str(ROOT / "include"), "-fPIC",
               "-ftls-model=initial-exec", "-fstack-protector-strong",
               # The Rust libc owns the matching init/fini entries.  Do not
               # let the fixed C backend install a second hidden constructor.
               common.MIMALLOC_LIFECYCLE_C_FLAG, *common.MIMALLOC_INTERNAL_VM_C_FLAGS,
               f"-ffile-prefix-map={ROOT}=/crabc", "-MD", "-MF", str(dependency_file)]
    if accepted_c:
        environment.update({"CC_x86_64_unknown_linux_musl": "/usr/bin/gcc",
                        "CFLAGS_x86_64_unknown_linux_musl": shlex.join(c_flags),
                        "CC_SHELL_ESCAPED_FLAGS": "1"})
    cargo = [rustup, "run", common.PINNED_TOOLCHAIN, "cargo"]
    features = ["x86-owned-dynamic-runtime" if accepted_c else "x86-owned-dynamic-native-shadow"]
    if lifecycle_test_audit:
        features.append("x86-owned-allocator-lifecycle-test-audit")
    dependency_graph = common.allocator_dependency_graph(cargo, ",".join(features),
                                                         "accepted-c" if accepted_c else allocator_backend, environment)
    libc_command = [*cargo, "rustc", "--locked", "-p", "crabc-libc", "--lib", "--release", "--no-default-features",
         "--features", ",".join(features), "--target", common.TARGET,
         "--target-dir", str(stage / "cargo"), "--", "--cfg", "crabc_owned_static_sysroot",
         "--cfg", common.MIMALLOC_LIFECYCLE_RUST_CFG,
         "-C", "relocation-model=pic", "-C", "panic=abort", "-Ztls-model=initial-exec",
         # C requires distinct functions to have distinct addresses; rustc's
         # identical-function merging would alias exports musl keeps apart.
         "-Zmerge-functions=disabled",
         "--remap-path-prefix", f"{ROOT}=/crabc"]
    # The linkage feature selects the general dlfcn bridge. The historical
    # static cfg remains for other shared source-owner visibility choices.
    run(libc_command, environment=environment)
    raw = stage / "cargo" / common.TARGET / "release/libc.a"
    backend_archive = common.selected_allocator_archive(stage / "cargo", "accepted-c" if accepted_c else allocator_backend)
    allocator_lifecycle = (common.owned_mimalloc_lifecycle_profile(
        c_flags, libc_command, backend_archive, raw,
        llvm_ar=ar, llvm_nm=nm, llvm_objdump=objdump,
        stage=stage / "allocator-lifecycle-profile",
    ) if accepted_c else {
        "initialization": "owned_dynamic_runtime::prepare-before-constructors",
        "process_done": "libc-fini-array-at-loader-graph-position-before-stdio-flush",
        "post_done_backing": "source-default-release-retained",
        "loader_allocator_pointer_transfer": False,
    })
    member = None
    if backend_archive is not None:
        backend_members = run([ar, "t", str(backend_archive)]).decode().splitlines()
        if len(backend_members) != 1:
            raise common.BuildError("accepted allocator archive must have one object")
        member = backend_members[0]
    members = tuple(run([ar, "t", str(raw)]).decode().splitlines())
    selected, excluded = select_allocator_members(members, member, allocator_backend)
    if member is not None:
        if run([ar, "p", str(raw), member]) != run([ar, "p", str(backend_archive), member]):
            raise common.BuildError("Cargo allocator member differs from attested backend")
    objects = stage / "objects"
    objects.mkdir()
    run([ar, "x", str(raw), *selected], cwd=objects)
    pinned_c_evidence = None
    if evidence_c:
        # Evidence only: the exact pinned v3.5.0 object replaces the accepted
        # libmimalloc-sys member; its locally-bound export set follows the
        # default-visibility rule the helper proves on the accepted member.
        evidence_object, pinned_c_evidence = common.pinned_c_evidence_object(
            stage, c_flags, backend_archive, llvm_ar=ar, environment=environment)
        common.require_no_implicit_lifecycle(evidence_object, llvm_nm=nm, llvm_objdump=objdump)
        (objects / member).unlink()
        common.copy_artifact(evidence_object, objects / evidence_object.name)
        selected = tuple(evidence_object.name if item == member else item for item in selected)
        hidden = pinned_c_evidence["default_visibility_definitions"]
        script = stage / "libc-mimalloc-hidden.exports"
        script.write_text("{\n  local:\n" + "".join(f"    {name};\n" for name in hidden) + "};\n", encoding="utf-8")
        shared_mimalloc_hidden_exports = {
            "source": "pinned-c-evidence default-visibility definitions",
            "member_count": len(hidden), "members": hidden,
            "linker_script_sha256": common.sha256_file(script), "linker_policy": "exact-local-symbols",
        }
    builtins = stage / "libcrabc-builtins.a"
    run([sys.executable, str(ROOT / "builtins/build_x86_64.py"), "--output", str(builtins),
         "--provenance", str(stage / "builtins.json"), "--verify-reproducible"])
    output.mkdir()
    library = output / "usr/lib"
    library.mkdir(parents=True)
    headers = common.install_header_tree(output / "usr/include")
    # Musl's configure applies its dynamic list to libc.so only. It binds
    # ordinary internal libc calls locally while retaining its data and
    # allocation interposition scope. The two exact version scripts remain
    # separate: mimalloc names are fixed-C private metadata, while errno's
    # one weak alias needs LLD localization after its allocator object edge
    # has resolved.
    shared_symbol_order = shared_libc_symbol_order(
        nm, [*(objects / item for item in selected), builtins], stage)
    shared_hot_rodata = shared_libc_hot_rodata([objects / item for item in selected], stage)
    libc_shared_link_command = shared_libc_link_command(
        lld, SHARED_LIBC_DYNAMIC_LIST, (stage / "libc-mimalloc-hidden.exports" if accepted_c else None),
        stage / "libc-errno-private.exports", stage / "libc-hot.order", stage / "libc-hot-rodata.ld",
        objects, selected, builtins, library
    )
    run(libc_shared_link_command)
    # The sealed dynamic product gives its one shared-library link role an
    # executable installed mode.  Every other finite link role is materialized
    # as a non-executable regular file below.
    (library / "libc.so").chmod(0o755)
    undefined = run([nm, "--undefined-only", str(library / "libc.so")]).decode().splitlines()
    allowed = {"__crabc_x86_64_initial_tls_allocate", "__crabc_x86_64_initial_tls_release",
               "__crabc_x86_64_resolve_initial_tls", "__crabc_x86_64_reset_current_tls_v1",
               "__crabc_x86_64_reset_current_tls_v2",
               "__crabc_x86_64_loader_conventional_startup_v1",
               "__crabc_x86_64_runtime_publish_initial_tid",
               "__crabc_x86_64_runtime_fork_prepare", "__crabc_x86_64_runtime_fork_complete",
               "__crabc_x86_64_runtime_open", "__crabc_x86_64_runtime_symbol",
               "__crabc_x86_64_runtime_close", "__crabc_x86_64_runtime_address",
               "__crabc_x86_64_runtime_information", "__crabc_x86_64_runtime_iterate"}
    unexpected = [line for line in undefined if line.split()[-1] not in allowed]
    if unexpected:
        raise common.BuildError(f"shared libc has unexpected unresolved symbols: {unexpected}")
    crt = stage / "crt"
    run([sys.executable, str(ROOT / "crt/build_x86_64.py"), "--owned-dynamic-sysroot",
         "--out-dir", str(crt), "--llvm-objdump", objdump])
    # This explicit CRT mode selects the authenticated dynamic-PIE Scrt1.o.
    # Its crt1.o, crti.o and crtn.o are byte-identical to the static
    # product's: one crt1.o serves static ET_EXEC and dynamic non-PIE.
    for name in ("crt1.o", "Scrt1.o", "crti.o", "crtn.o"):
        common.copy_artifact(crt / name, library / name)
    # Main-resident attachment preserves the established main-only weak wire.
    # It also carries the CRT's owned-handoff slot reader, which the combined
    # crt1.o must not import itself because static executables link it too.
    attachment_parts = stage / "dynamic-attachment"
    attachment_parts.mkdir()
    handoff_reader_command = [rustup, "run", common.PINNED_TOOLCHAIN, "rustc", "--edition=2021",
                              "--crate-name", "crabc_owned_crt_handoff_attachment", "--crate-type", "lib",
                              "--emit", "obj", "-C", "opt-level=2", "-C", "panic=abort",
                              "-C", "relocation-model=pic", "--remap-path-prefix", f"{ROOT}=/crabc",
                              str(ROOT / "crt/src/x86_64_owned_crt_handoff_attachment.rs"),
                              "-o", str(attachment_parts / "crt-handoff-reader.o")]
    run(handoff_reader_command)
    run([rustup, "run", common.PINNED_TOOLCHAIN, "rustc", "--edition=2021",
         "--crate-name", "crabc_dynamic_attachment", "--crate-type", "lib", "--emit=obj",
         "-C", "opt-level=2", "-C", "panic=abort", "-C", "relocation-model=pic",
         "--remap-path-prefix", f"{ROOT}=/crabc",
         str(ROOT / "libc/src/c_abi/x86_64/owned_dynamic_attachment.rs"),
         "-o", str(attachment_parts / "libc-attachment.o")])
    run([str(lld), "-r", str(attachment_parts / "libc-attachment.o"),
         str(attachment_parts / "crt-handoff-reader.o"), "-o", str(library / "crabc-dynamic-attach.o")])
    (library / "crabc-dynamic-attach.o").chmod(0o644)
    common.copy_artifact(builtins, library / builtins.name)
    loader_env = common.deterministic_environment()
    loader_env["CARGO_BUILD_JOBS"] = "2"
    loader_env["RUSTFLAGS"] = ("-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic"
                              f" -C link-arg=-Wl,-T,{RUNTIME_DISCARD_UNWIND_SCRIPT}"
                              f" -C link-arg=-Wl,-T,{LOADER_BSS_LAYOUT_SCRIPT}")
    # Every process touches nearly all interpreter text, so it is optimized
    # for size: opt-level s cuts it from 135 to 81 KiB (54 KiB of PSS per
    # process) for about 2% more fork+exec CPU and 8% slower dlsym.
    loader_command = [*cargo, "build", "--locked", "-p", "crabc-ldso", "--release",
                      "--config", 'profile.release.opt-level="s"', "--target", common.TARGET,
                      "--target-dir", str(stage / "loader"), "--no-default-features", "--features",
                      LOADER_FEATURE]
    run(loader_command, environment=loader_env)
    interpreter = output / "lib/ld-crabc-x86_64.so.1"
    loader_artifact = stage / "loader" / common.TARGET / "release/libldso.so"
    common.copy_artifact(loader_artifact, interpreter)
    interpreter.chmod(0o755)
    if allocator_backend == "native-shadow":
        native_definitions = elf_symbols(nm, library / "libc.so", "--defined-only")
        native_imports = elf_symbols(nm, library / "libc.so", "--undefined-only")
        loader_imports = elf_symbols(nm, interpreter, "--undefined-only")
        loader_definitions = elf_symbols(nm, interpreter, "--defined-only")
        validate_native_allocator_symbols(native_definitions, native_imports, loader_imports | loader_definitions)
        if "__crabc_x86_native_mimalloc_process_finalizer" not in native_definitions:
            raise common.BuildError("native shared libc lost its private ELF process finalizer")
        common.write_json(stage / "native-allocator-symbols.json", {
            "definitions": sorted(native_definitions), "imports": sorted(native_imports),
            "loader_imports": sorted(loader_imports), "loader_definitions": sorted(loader_definitions),
        })
    libc_elf = audit_shared_elf(library / "libc.so")
    loader_elf = audit_shared_elf(interpreter)
    (interpreter.parent / "ld-musl-x86_64.so.1").symlink_to(interpreter.name)
    metadata = output / "share/crabc"
    metadata.mkdir(parents=True)
    if allocator_backend == "native-shadow":
        common.copy_artifact(stage / "native-allocator-symbols.json", metadata / "native-allocator-symbols.json")
    common.copy_artifact(crt / "objects.json", metadata / "crt.provenance.json")
    common.copy_artifact(crt / "commands.json", metadata / "crt.commands.json")
    common.copy_artifact(stage / "builtins.json", metadata / "builtins.provenance.json")
    common.write_json(metadata / "producer-tools.json", tools)
    common.write_json(metadata / "libc-shared.elf.json", libc_elf)
    common.write_json(metadata / "loader.elf.json", loader_elf)
    common.write_json(
        metadata / "loader.provenance.json",
        loader_provenance(stage, loader_command, loader_env["RUSTFLAGS"], loader_artifact, interpreter),
    )
    for source, name in ((ROOT / "compat/x86_64/crabc_cc_owned_dynamic.py", "bin/crabc-cc-dynamic"),
                         (ROOT / "compat/x86_64/crabc_cc_static.py", "share/crabc/crabc_cc_static.py"),
                         (ROOT / "compat/x86_64/owned_dynamic_receipt.py", "share/crabc/owned_dynamic_receipt.py"),
                         (ROOT / "compat/x86_64/owned_dynamic_elf.py", "share/crabc/owned_dynamic_elf.py")):
        common.copy_artifact(source, output / name)
    (output / "bin/crabc-cc-dynamic").chmod(0o755)
    provenance = {"selected_members": {item: common.sha256_file(objects / item) for item in selected},
                  "excluded_members": list(excluded),
                  "allocator_backend": recorded_backend,
                  "allocator_lifecycle_test_audit": lifecycle_test_audit,
                  "accepted_allocator": (common.accepted_allocator_pin() if accepted_c else None),
                  "pinned_c_evidence": pinned_c_evidence,
                  "native_allocator": (_source_file_identity(ROOT / "crabc-mimalloc/UPSTREAM.md", "fixed native allocator provenance") if allocator_backend == "native-shadow" else None),
                  "dependency_graph": dependency_graph,
                  "excluded_c_allocator": None,
                  "allocator_headers": (common.allocator_header_provenance(dependency_file, Path(environment["CARGO_HOME"])) if accepted_c else None),
                  "allocator_compiler": (common.executable_identity(Path("/usr/bin/gcc"), "pinned allocator C compiler") if accepted_c else None),
                  "allocator_flags": ([flag.replace(str(stage), "$BUILD").replace(str(ROOT), "$SOURCE") for flag in c_flags] if accepted_c else []),
                  "allocator_lifecycle_profile": allocator_lifecycle,
                  "libc_command": [arg.replace(str(stage), "$BUILD").replace(str(ROOT), "$SOURCE") for arg in libc_command],
                  "libc_shared_link_command": [_normalized_loader_argument(arg, stage) for arg in libc_shared_link_command],
                  "shared_dynamic_list": shared_dynamic_list,
                  "shared_mimalloc_hidden_exports": shared_mimalloc_hidden_exports,
                  "shared_compiler_helper_archive": shared_compiler_helper_policy,
                  "shared_errno_private_aliases": shared_errno_private_aliases,
                  "shared_symbol_order": shared_symbol_order,
                  "shared_hot_rodata": shared_hot_rodata,
                  "discard_unwind_script": _source_file_identity(RUNTIME_DISCARD_UNWIND_SCRIPT, "runtime unwind-table discard script"),
                  "loader_imports": sorted(allowed)}
    common.write_json(metadata / "libc-shared.provenance.json", provenance)
    payload_files = {path.relative_to(output).as_posix(): common.sha256_file(path)
                     for path in sorted(output.rglob("*")) if path.is_file() and not path.is_symlink()}
    common.write_json(metadata / "dynamic-product-state.json", {
        "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
        "status": "materialized-unqualified", "source_sha256": qualification.source_digest(),
        "allocator_backend": recorded_backend, "allocator_lifecycle_test_audit": lifecycle_test_audit,
        "allocator_promoted": False,
        "contracts": qualification.contract_digests(), "payload_files": payload_files,
        "runtime_v1_published": False, "campaign_complete": False, "public_support": False,
        "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
        "runtime_profile": qualification.MATERIALIZATION_PROFILE,
        "qualification": qualification.MATERIALIZATION_QUALIFICATION})
    write_product_manifest(output, metadata)


def build_debug_payload(output: Path, stage: Path, *, allocator_backend: str, lifecycle_test_audit: bool) -> None:
    """Link opt0 source-built runtime objects without using installed Rust runtimes."""
    inputs = common.build_debug_runtime_inputs(stage, allocator_backend=allocator_backend,
                                               lifecycle_test_audit=lifecycle_test_audit, dynamic=True)
    tools = inputs["producer_tools"]
    ar = common.producer_tool_path(tools, "llvm-ar")
    nm = common.producer_tool_path(tools, "llvm-nm")
    rustup = tools["rustup"]["path"]
    sysroot = common.pinned_rustc_sysroot(Path(rustup))
    lld = sysroot / "lib/rustlib" / common.TARGET / "bin/gcc-ld/ld.lld"
    run = common.run
    objects = inputs["source_objects"]
    builtins = inputs["builtins"]
    core = inputs["source_core"]
    compiler = inputs["source_compiler_builtins"]
    selected = [row["name"] for row in inputs["libc_provenance"]["selected_members"]]
    core_members = set(run([ar, "t", str(core)]).decode().splitlines())
    private_core = stage / "libcrabc-source-core.a"
    run([ar, "rcsD", str(private_core), *(str(objects / name) for name in selected if name in core_members)])
    selected = [name for name in selected if name not in core_members]
    output.mkdir()
    library = output / "usr/lib"
    library.mkdir(parents=True)
    headers = common.install_header_tree(output / "usr/include")
    accepted_c = common.backend_selection(allocator_backend, lifecycle_test_audit) == "accepted-c"
    dynamic_list = shared_libc_dynamic_list()
    errno_policy = shared_libc_errno_private_aliases(stage)
    allocator_policy = shared_libc_mimalloc_hidden_exports(stage) if accepted_c else {"status": "not-selected-native-shadow"}
    rust_private = stage / "libc-rust-private.exports"
    rust_private.write_text("{ local: _R*; _ZN*; };\n")
    libc_command = [str(lld), "-shared", "--hash-style=sysv", "--eh-frame-hdr", "-soname", "libc.so",
                    f"--dynamic-list={SHARED_LIBC_DYNAMIC_LIST}",
                    f"--version-script={rust_private}",
                    f"--version-script={stage / 'libc-errno-private.exports'}",
                    *([f"--version-script={stage / 'libc-mimalloc-hidden.exports'}"] if accepted_c else []),
                    "--exclude-libs=libcrabc-builtins.a,libcrabc-source-core.a", "--gc-sections",
                    "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
                    *(str(objects / name) for name in selected), str(private_core), str(builtins),
                    str(RUNTIME_DISCARD_UNWIND_SCRIPT), "-o", str(library / "libc.so")]
    run(libc_command)
    (library / "libc.so").chmod(0o755)
    allowed = {"__crabc_x86_64_initial_tls_allocate", "__crabc_x86_64_initial_tls_release",
               "__crabc_x86_64_resolve_initial_tls", "__crabc_x86_64_reset_current_tls_v1",
               "__crabc_x86_64_reset_current_tls_v2", "__crabc_x86_64_loader_conventional_startup_v1",
               "__crabc_x86_64_runtime_publish_initial_tid", "__crabc_x86_64_runtime_fork_prepare",
               "__crabc_x86_64_runtime_fork_complete", "__crabc_x86_64_runtime_open", "__crabc_x86_64_runtime_symbol",
               "__crabc_x86_64_runtime_close", "__crabc_x86_64_runtime_address", "__crabc_x86_64_runtime_information",
               "__crabc_x86_64_runtime_iterate"}
    imports = elf_symbols(nm, library / "libc.so", "--undefined-only")
    if imports - allowed:
        raise common.BuildError(f"debug shared libc has unexpected unresolved symbols: {sorted(imports - allowed)}")
    crt = inputs["crt_root"]
    for name in ("crt1.o", "Scrt1.o", "crti.o", "crtn.o"):
        common.copy_artifact(crt / name, library / name)
    common.copy_artifact(builtins, library / builtins.name)
    base = [rustup, "run", common.PINNED_TOOLCHAIN, "rustc", "--edition=2021", "--crate-type=lib",
            "--target", common.TARGET, "-Zunstable-options", "-Cpanic=immediate-abort", "-Copt-level=0",
            "-Cforce-unwind-tables=no", "-Cdebuginfo=0", "-Coverflow-checks=off", "-Cdebug-assertions=off",
            "-Crelocation-model=pic", "--remap-path-prefix", f"{ROOT}=/crabc",
            "--extern", f"noprelude:core={core.with_suffix('.rmeta')}",
            "--extern", f"noprelude:compiler_builtins={compiler.with_suffix('.rmeta')}",
            "-L", f"dependency={core.parent}"]
    attachment_parts = stage / "dynamic-attachment"
    attachment_parts.mkdir()
    attachment_commands = []
    for source, name in ((ROOT / "libc/src/c_abi/x86_64/owned_dynamic_attachment.rs", "libc-attachment"),
                         (ROOT / "crt/src/x86_64_owned_crt_handoff_attachment.rs", "crt-handoff-reader")):
        command = [*base, "--emit=obj", "--crate-name", name.replace("-", "_"), str(source),
                   "-o", str(attachment_parts / (name + ".o"))]
        run(command)
        attachment_commands.append(command)
    parts = list(attachment_parts.glob("*.o"))
    # CRT and helper calls must bind to the same freshly compiled core. Pull
    # exactly their unresolved core providers into the main-resident role;
    # section collection keeps unrelated core helpers outside the closure.
    dependencies = set()
    definitions = elf_symbols(nm, private_core, "--defined-only")
    for artifact in [*parts, *(crt / name for name in ("crt1.o", "Scrt1.o", "crti.o", "crtn.o")), builtins]:
        dependencies.update(elf_symbols(nm, artifact, "--undefined-only") & definitions)
    support = stage / "main-core-support.o"
    support_command = [str(lld), "-r", "--gc-sections", *(f"--undefined={name}" for name in sorted(dependencies)),
                       str(private_core), "-o", str(support)]
    run(support_command)
    attachment_command = [str(lld), "-r", *(str(part) for part in parts), str(support),
                          "-o", str(library / "crabc-dynamic-attach.o")]
    run(attachment_command)
    loader_object = stage / "loader.o"
    loader_dependencies = stage / "loader.d"
    cfgs = [f'feature="{feature}"' for feature in (LOADER_FEATURE, "x86_64-general-initial-interpreter",
             "x86_64-general-initial-lifecycle", "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter")]
    cfgs.extend(("crabc_general_initial_graph", "crabc_general_initial_lifecycle",
                 "crabc_general_initial_tls_materialization_v1", "crabc_general_loader_libc_tls_runtime_v1",
                 "crabc_dynamic_main_thread_runtime_v1"))
    loader_command = [*base, "--crate-name", "crabc_owned_debug_loader", f"--emit=obj,dep-info={loader_dependencies}",
                      *(argument for cfg in cfgs for argument in ("--cfg", cfg)),
                      str(ROOT / "ldso/src/lib.rs"), "-o", str(loader_object)]
    run(loader_command)
    private_exports = stage / "loader-private.exports"
    private_exports.write_text("{ local: _R*; _ZN*; };\n")
    interpreter = output / LOADER_ARTIFACT
    interpreter.parent.mkdir()
    loader_link = [str(lld), "-shared", "-Bsymbolic", "--hash-style=sysv", "-e", "_start", "--no-undefined",
                   "-z", "now", "-z", "noexecstack", f"--version-script={private_exports}",
                   "--exclude-libs=libcrabc-source-core.a,libcrabc-builtins.a", str(loader_object),
                   str(private_core), str(builtins), str(RUNTIME_DISCARD_UNWIND_SCRIPT), str(LOADER_BSS_LAYOUT_SCRIPT),
                   "-o", str(interpreter)]
    run(loader_link)
    interpreter.chmod(0o755)
    (interpreter.parent / "ld-musl-x86_64.so.1").symlink_to(interpreter.name)
    metadata = output / "share/crabc"
    metadata.mkdir(parents=True)
    common.write_json(metadata / "headers.provenance.json", headers)
    for source, name in ((crt / "objects.json", "crt.provenance.json"), (crt / "commands.json", "crt.commands.json"),
                         (inputs["builtins_provenance"], "builtins.provenance.json")):
        common.copy_artifact(source, metadata / name)
    common.write_json(metadata / "producer-tools.json", tools)
    common.write_json(metadata / "libc-shared.elf.json", audit_shared_elf(library / "libc.so"))
    common.write_json(metadata / "loader.elf.json", audit_shared_elf(interpreter))
    common.write_json(metadata / "libc-shared.provenance.json", {**inputs["libc_provenance"],
        "shared_dynamic_list": dynamic_list, "shared_errno_private_aliases": errno_policy,
        "shared_mimalloc_hidden_exports": allocator_policy, "libc_shared_link_command": libc_command,
        "main_source_core_dependencies": sorted(dependencies), "main_source_core_link_command": support_command,
        "attachment_compile_commands": attachment_commands, "attachment_link_command": attachment_command})
    common.write_json(metadata / "loader.provenance.json", {"build_profile": "debug", "target": common.TARGET,
        "compiler_command": loader_command, "link_command": loader_link,
        "compiler_dependencies": loader_dependency_provenance(loader_dependencies, loader_object, object_dependencies=True),
        "feature_configuration": _source_file_identity(ROOT / "ldso/build.rs", "loader feature configuration"),
        "source_core_archive_sha256": common.sha256_file(core), "source_helper_archive_sha256": common.sha256_file(builtins),
        "artifact": {"path": LOADER_ARTIFACT, "sha256": common.sha256_file(interpreter)}})
    for source, name in ((ROOT / "compat/x86_64/crabc_cc_owned_dynamic.py", "bin/crabc-cc-dynamic"),
                         (ROOT / "compat/x86_64/crabc_cc_static.py", "share/crabc/crabc_cc_static.py"),
                         (ROOT / "compat/x86_64/owned_dynamic_receipt.py", "share/crabc/owned_dynamic_receipt.py"),
                         (ROOT / "compat/x86_64/owned_dynamic_elf.py", "share/crabc/owned_dynamic_elf.py")):
        common.copy_artifact(source, output / name)
    (output / "bin/crabc-cc-dynamic").chmod(0o755)
    common.write_json(metadata / "dynamic-product-state.json", {"build_profile": "debug", "allocator_backend": allocator_backend,
        "allocator_lifecycle_test_audit": lifecycle_test_audit, "status": "materialized-unqualified"})
    write_product_manifest(output, metadata, profile="debug")


def write_product_manifest(output: Path, metadata: Path, *, profile: str = "release") -> None:
    """Seal installed payload bytes together with their selected Rust toolchain."""
    files = {path.relative_to(output).as_posix(): common.sha256_file(path)
             for path in sorted(output.rglob("*")) if path.is_file() and not path.is_symlink()}
    manifest = {"schema": 1, "format": FORMAT,
        "target": common.TARGET, "toolchain": common.PINNED_TOOLCHAIN, "files": files, "build_profile": profile,
        "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}}
    if profile == "debug":
        # Debug state describes only the unqualified backend selection. Bind
        # its installed payload to source content in the manifest; build()
        # also requires this fingerprint to match the one taken before build.
        manifest["source_sha256"] = qualification.source_digest()
    common.write_json(metadata / "manifest.json", manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allocator-backend", choices=ALLOCATOR_BACKENDS, default=common.DEFAULT_ALLOCATOR_BACKEND)
    parser.add_argument("--allocator-lifecycle-test-audit", action="store_true")
    parser.add_argument("--profile", choices=("release", "debug"), default="release")
    args = parser.parse_args()
    try:
        build(args.output, allocator_backend=args.allocator_backend, lifecycle_test_audit=args.allocator_lifecycle_test_audit, profile=args.profile)
    except (common.BuildError, OSError) as error:
        print(f"owned dynamic sysroot: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
