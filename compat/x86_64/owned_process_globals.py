#!/usr/bin/env python3
"""Structural provider closure for the frozen x86 `process.globals` roster.

The frozen AArch64 capability ledger names 31 process-global spellings. This
reader compares their ELF provider metadata in the owned static archive and
shared libc with the pinned musl 1.2.6 x86-64 `libc.a` and `libc.so`:

* each spelling has exactly one defined provider in each artifact, with
  musl's type, binding, visibility, and object size, and no symbol version;
* each static provider is reachable through the archive index from the one
  member that defines it, so ordinary demand-driven extraction selects it;
* the same-storage alias partition (member/section/value) equals musl's;
* a non-PIE dynamic consumer that reads the data spellings directly carries
  R_X86_64_COPY storage for them, and its executable-defined copies keep the
  same alias partition as libc.so.

Function sizes are code, not ABI, and are only required to be nonzero. The
module performs no compilation, linking, or execution; the native runner
(`run_owned_process_globals.sh`) supplies `readelf`/`nm` transcripts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
COVERAGE = ROOT / "compat" / "crabc-rs" / "coverage.toml"
CAPABILITY = "process.globals"

# The frozen roster, split by ELF symbol type. The ledger is authoritative;
# this copy exists so that a ledger drift fails loudly instead of silently
# widening or shrinking the audited closure.
DATA_NAMES = (
    "___environ", "__daylight", "__environ", "__optpos", "__optreset",
    "__progname", "__progname_full", "__signgam", "__timezone", "__tzname",
    "_environ", "daylight", "environ", "h_errno", "optarg", "opterr",
    "optind", "optopt", "optreset", "program_invocation_name",
    "program_invocation_short_name", "signgam", "timezone", "tzname",
)
FUNCTION_NAMES = (
    "__h_errno_location", "__posix_getopt", "getenv", "getopt", "getopt_long",
    "getopt_long_only", "putenv",
)
ROSTER = tuple(sorted(DATA_NAMES + FUNCTION_NAMES))

_SYMBOL_ROW = re.compile(
    r"^\s*\d+:\s+(?P<value>[0-9a-fA-F]+)\s+(?P<size>0x[0-9a-fA-F]+|\d+)\s+"
    r"(?P<type>\S+)\s+(?P<bind>\S+)\s+(?P<vis>\S+)\s+(?P<ndx>\S+)"
    r"(?:\s+(?P<name>\S+))?\s*$"
)
_FILE_ROW = re.compile(r"^File: .*\((?P<member>[^()]+)\)\s*$")
_RELOCATION_ROW = re.compile(
    r"^\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+(?P<type>R_X86_64_\w+)\s+"
    r"[0-9a-fA-F]+\s+(?P<name>[^\s+]+)"
)


class ProcessGlobalsError(ValueError):
    """The provider closure differs from pinned musl or cannot be read."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProcessGlobalsError(message)


@dataclass(frozen=True)
class Definition:
    """One defined ELF symbol row, with its archive member when applicable."""

    name: str
    version: str
    member: str
    section: str
    value: int
    size: int
    type: str
    binding: str
    visibility: str

    def storage(self) -> tuple[str, str, int]:
        return (self.member, self.section, self.value)


def frozen_roster(coverage: Path = COVERAGE) -> tuple[str, ...]:
    """Return the ledger's exact roster, rejecting drift from this reader."""
    try:
        with coverage.open("rb") as stream:
            ledger = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProcessGlobalsError(f"cannot read capability ledger: {error}") from error
    matches = [
        entry for entry in ledger.get("capability", [])
        if isinstance(entry, Mapping) and entry.get("id") == CAPABILITY
    ]
    require(len(matches) == 1, f"capability ledger must name {CAPABILITY} once")
    symbols = matches[0].get("symbols")
    require(
        isinstance(symbols, list) and all(isinstance(item, str) for item in symbols),
        f"{CAPABILITY} symbol roster is invalid",
    )
    require(
        tuple(sorted(symbols)) == ROSTER and len(symbols) == len(set(symbols)),
        f"{CAPABILITY} frozen roster differs from the audited 31-name closure",
    )
    return ROSTER


def parse_symbols(transcript: str) -> list[Definition]:
    """Parse `readelf --symbols/--dyn-syms --wide` rows for defined globals.

    Archive transcripts carry `File: archive(member)` headers; shared-object
    and executable transcripts use the empty member. Local and undefined rows
    are not providers and are omitted.
    """
    member = ""
    rows: list[Definition] = []
    for raw in transcript.splitlines():
        file_match = _FILE_ROW.match(raw)
        if file_match is not None:
            member = file_match["member"]
            continue
        match = _SYMBOL_ROW.match(raw)
        if match is None or not match["name"]:
            continue
        if match["ndx"] == "UND" or match["bind"] == "LOCAL":
            continue
        spelling = match["name"]
        name, _, version = spelling.partition("@")
        rows.append(Definition(
            name=name,
            version=version,
            member=member,
            section=match["ndx"],
            value=int(match["value"], 16),
            size=int(match["size"], 0),
            type=match["type"],
            binding=match["bind"],
            visibility=match["vis"],
        ))
    return rows


def parse_archive_index(transcript: str) -> dict[str, set[str]]:
    """Parse `nm --print-armap` `NAME in MEMBER` index rows."""
    index: dict[str, set[str]] = {}
    for raw in transcript.splitlines():
        parts = raw.split(" in ")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            continue
        index.setdefault(parts[0].strip(), set()).add(parts[1].strip())
    return index


def parse_copy_relocations(transcript: str) -> set[str]:
    """Return symbol names carried by R_X86_64_COPY in `readelf --relocs`."""
    names: set[str] = set()
    for raw in transcript.splitlines():
        match = _RELOCATION_ROW.match(raw)
        if match is not None and match["type"] == "R_X86_64_COPY":
            names.add(match["name"].partition("@")[0])
    return names


def providers(rows: Iterable[Definition], artifact: str) -> dict[str, Definition]:
    """Select exactly one defined provider for every roster name."""
    selected: dict[str, list[Definition]] = {name: [] for name in ROSTER}
    for row in rows:
        if row.name in selected:
            selected[row.name].append(row)
    result: dict[str, Definition] = {}
    for name, found in selected.items():
        require(found, f"{artifact} does not define {name}")
        require(len(found) == 1, f"{artifact} defines {name} {len(found)} times")
        result[name] = found[0]
    return result


def alias_partition(definitions: Mapping[str, Definition]) -> frozenset[frozenset[str]]:
    """Group roster names that name one storage location or entry point."""
    groups: dict[tuple[str, str, int], set[str]] = {}
    for name, definition in definitions.items():
        groups.setdefault(definition.storage(), set()).add(name)
    return frozenset(frozenset(group) for group in groups.values())


def _describe(partition: frozenset[frozenset[str]]) -> list[list[str]]:
    return sorted(sorted(group) for group in partition if len(group) > 1)


def compare_providers(
    candidate: Mapping[str, Definition],
    reference: Mapping[str, Definition],
    artifact: str,
) -> None:
    """Require musl's per-name metadata and alias partition."""
    for name in ROSTER:
        have, want = candidate[name], reference[name]
        expected_type = "OBJECT" if name in DATA_NAMES else "FUNC"
        require(want.type == expected_type, f"pinned musl {artifact} {name} is not {expected_type}")
        require(have.type == want.type, f"{artifact} {name} type {have.type} differs from musl {want.type}")
        require(
            have.binding == want.binding,
            f"{artifact} {name} binding {have.binding} differs from musl {want.binding}",
        )
        require(
            have.visibility == want.visibility == "DEFAULT",
            f"{artifact} {name} visibility {have.visibility} differs from musl {want.visibility}",
        )
        require(have.version == want.version == "", f"{artifact} {name} must be unversioned")
        if expected_type == "OBJECT":
            require(have.size == want.size, f"{artifact} {name} size {have.size} differs from musl {want.size}")
        else:
            require(have.size > 0, f"{artifact} {name} has no code size")
    have_partition = alias_partition(candidate)
    want_partition = alias_partition(reference)
    require(
        have_partition == want_partition,
        f"{artifact} alias partition {_describe(have_partition)} differs from musl "
        f"{_describe(want_partition)}",
    )


def audit_static(
    candidate_symbols: str,
    candidate_index: str,
    reference_symbols: str,
    reference_index: str,
) -> dict[str, object]:
    """Compare owned `libc.a` providers and extraction with musl `libc.a`."""
    candidate = providers(parse_symbols(candidate_symbols), "owned libc.a")
    reference = providers(parse_symbols(reference_symbols), "pinned musl libc.a")
    compare_providers(candidate, reference, "owned libc.a")
    for label, definitions, transcript in (
        ("owned libc.a", candidate, candidate_index),
        ("pinned musl libc.a", reference, reference_index),
    ):
        index = parse_archive_index(transcript)
        for name, definition in definitions.items():
            require(
                index.get(name) == {definition.member},
                f"{label} archive index does not extract {name} from {definition.member}",
            )
    return {
        "names": len(candidate),
        "members": sorted({definition.member for definition in candidate.values()}),
        "aliases": _describe(alias_partition(candidate)),
    }


def audit_shared(candidate_symbols: str, reference_symbols: str) -> dict[str, object]:
    """Compare owned `libc.so` dynamic providers with musl `libc.so`."""
    candidate = providers(parse_symbols(candidate_symbols), "owned libc.so")
    reference = providers(parse_symbols(reference_symbols), "pinned musl libc.so")
    compare_providers(candidate, reference, "owned libc.so")
    return {"names": len(candidate), "aliases": _describe(alias_partition(candidate))}


def audit_copy_executable(
    executable_symbols: str,
    executable_relocations: str,
    library_symbols: str,
    label: str,
) -> dict[str, object]:
    """Require executable COPY storage for every data spelling it reads.

    The non-PIE consumer names all 24 data spellings. Each must be defined by
    the executable itself (the linker's copy, or an alias of a copy) and the
    executable's alias partition must equal the library's; at least one
    R_X86_64_COPY must carry each storage group.
    """
    executable = {
        row.name: row for row in parse_symbols(executable_symbols)
        if row.name in DATA_NAMES
    }
    library = providers(parse_symbols(library_symbols), f"{label} libc.so")
    copies = parse_copy_relocations(executable_relocations)
    for name in DATA_NAMES:
        require(name in executable, f"{label} executable does not own COPY storage for {name}")
    have = alias_partition(executable)
    want = alias_partition({name: library[name] for name in DATA_NAMES})
    require(
        have == want,
        f"{label} executable COPY alias partition {_describe(have)} differs from libc.so {_describe(want)}",
    )
    for group in want:
        require(group & copies, f"{label} executable has no R_X86_64_COPY for {sorted(group)}")
    return {"copied": sorted(copies & set(DATA_NAMES)), "groups": len(want)}


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ProcessGlobalsError(f"cannot read {path}: {error}") from error


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("roster")
    static = commands.add_parser("static")
    static.add_argument("candidate_symbols")
    static.add_argument("candidate_index")
    static.add_argument("reference_symbols")
    static.add_argument("reference_index")
    shared = commands.add_parser("shared")
    shared.add_argument("candidate_symbols")
    shared.add_argument("reference_symbols")
    copy = commands.add_parser("copy")
    copy.add_argument("label")
    copy.add_argument("executable_symbols")
    copy.add_argument("executable_relocations")
    copy.add_argument("library_symbols")
    options = parser.parse_args(arguments)

    frozen_roster()
    if options.command == "roster":
        report: object = list(ROSTER)
    elif options.command == "static":
        report = audit_static(
            _read(options.candidate_symbols), _read(options.candidate_index),
            _read(options.reference_symbols), _read(options.reference_index),
        )
    elif options.command == "shared":
        report = audit_shared(_read(options.candidate_symbols), _read(options.reference_symbols))
    else:
        report = audit_copy_executable(
            _read(options.executable_symbols), _read(options.executable_relocations),
            _read(options.library_symbols), options.label,
        )
    json.dump(report, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProcessGlobalsError as error:
        raise SystemExit(f"x86 process.globals provider closure: {error}") from error
