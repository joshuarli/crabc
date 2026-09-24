#!/usr/bin/env python3
"""Structural provider closure for frozen x86 C-ABI capability rosters.

The frozen AArch64 capability ledger (`compat/crabc-rs/coverage.toml`) names
each capability's C spellings in `symbols`; `[[candidate_only]]` rows mark
the spellings that only the frozen crabc dynamic ABI exports. This reader compares the ELF provider
metadata of one or more capability rosters in the owned static archive and
shared libc with the pinned musl 1.2.6 x86-64 `libc.a` and `libc.so`:

* each spelling has exactly one defined provider in each artifact, with
  musl's type, binding, visibility, and object size, and no symbol version;
* each static provider is reachable through the archive index from the one
  member that defines it, so ordinary demand-driven extraction selects it;
* each spelling shares its storage (member/section/value) with exactly the
  spellings, roster or not, that share it in musl;
* a non-PIE dynamic consumer that reads the data spellings directly carries
  R_X86_64_COPY storage for them, and its executable-defined copies keep the
  same alias partition as libc.so.

The expected ELF type of every spelling comes from musl's `libc.a`, so a
roster needs no second hand-maintained copy. A `[[candidate_only]]` spelling
is by definition absent from musl's `libc.so` (musl keeps `__qsort_r` hidden);
the frozen crabc ABI exports it, so the owned `libc.so` must define it with
DEFAULT visibility and musl's static type and binding.

Function sizes are code, not ABI, and are only required to be nonzero. The
module performs no compilation, linking, or execution; the native runners
(`run_owned_process_globals.sh`, `run_owned_c_abi_compat.sh`) supply
`readelf`/`nm` transcripts.
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


class ProviderClosureError(ValueError):
    """The provider closure differs from pinned musl or cannot be read."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderClosureError(message)


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


@dataclass(frozen=True)
class Roster:
    """The frozen spellings of the selected capabilities."""

    capabilities: tuple[str, ...]
    names: tuple[str, ...]
    candidate_only: frozenset[str]


def frozen_roster(capabilities: Sequence[str], coverage: Path = COVERAGE) -> Roster:
    """Return the ledger roster of `capabilities`, each named exactly once."""
    require(bool(capabilities), "select at least one capability")
    require(len(set(capabilities)) == len(capabilities), "duplicate capability selection")
    try:
        with coverage.open("rb") as stream:
            ledger = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProviderClosureError(f"cannot read capability ledger: {error}") from error
    names: list[str] = []
    for capability in capabilities:
        matches = [
            entry for entry in ledger.get("capability", [])
            if isinstance(entry, Mapping) and entry.get("id") == capability
        ]
        require(len(matches) == 1, f"capability ledger must name {capability} once")
        symbols = matches[0].get("symbols")
        require(
            isinstance(symbols, list) and symbols
            and all(isinstance(item, str) for item in symbols),
            f"{capability} symbol roster is invalid",
        )
        names.extend(symbols)
    candidate_only = {
        entry["name"] for entry in ledger.get("candidate_only", [])
        if isinstance(entry, Mapping) and entry.get("capability") in capabilities
        and isinstance(entry.get("name"), str)
    }
    require(len(names) == len(set(names)), "selected capability rosters overlap")
    # A candidate-only row may restate a spelling its capability already lists.
    return Roster(
        tuple(capabilities), tuple(sorted(set(names) | candidate_only)), frozenset(candidate_only)
    )


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


def providers(
    rows: Iterable[Definition], names: Iterable[str], artifact: str
) -> dict[str, Definition]:
    """Select exactly one defined provider for every name."""
    selected: dict[str, list[Definition]] = {name: [] for name in names}
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
    """Group names that name one storage location or entry point."""
    groups: dict[tuple[str, str, int], set[str]] = {}
    for name, definition in definitions.items():
        groups.setdefault(definition.storage(), set()).add(name)
    return frozenset(frozenset(group) for group in groups.values())


def _describe(partition: frozenset[frozenset[str]]) -> list[list[str]]:
    return sorted(sorted(group) for group in partition if len(group) > 1)


def storage_peers(rows: Iterable[Definition], names: Iterable[str]) -> dict[str, frozenset[str]]:
    """Map each name to every singly-defined spelling at its storage.

    Only spellings in `names` are considered, so the caller chooses the
    comparable universe (names that both artifacts define exactly once).
    """
    universe = set(names)
    located: dict[str, Definition] = {}
    for row in rows:
        if row.name in universe:
            located[row.name] = row
    groups: dict[tuple[str, str, int], set[str]] = {}
    for name, definition in located.items():
        groups.setdefault(definition.storage(), set()).add(name)
    return {name: frozenset(groups[definition.storage()]) for name, definition in located.items()}


def _singly_defined(rows: Sequence[Definition]) -> set[str]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.name] = counts.get(row.name, 0) + 1
    return {name for name, count in counts.items() if count == 1}


def compare_providers(
    candidate: Mapping[str, Definition],
    reference: Mapping[str, Definition],
    candidate_rows: Sequence[Definition],
    reference_rows: Sequence[Definition],
    artifact: str,
) -> None:
    """Require the reference's per-name metadata and storage identity.

    Storage identity is compared across the whole artifact, not only the
    roster: a roster entry point must share its address with exactly the
    spellings that share it in musl. C gives distinct functions distinct
    addresses, so a compiler or linker that folds two identical bodies into
    one entry point is observable through function-pointer comparison.
    """
    for name, want in reference.items():
        have = candidate[name]
        require(want.type in ("OBJECT", "FUNC"), f"pinned musl {artifact} {name} is {want.type}")
        require(have.type == want.type, f"{artifact} {name} type {have.type} differs from musl {want.type}")
        require(
            have.binding == want.binding,
            f"{artifact} {name} binding {have.binding} differs from musl {want.binding}",
        )
        require(
            have.visibility == want.visibility,
            f"{artifact} {name} visibility {have.visibility} differs from musl {want.visibility}",
        )
        require(have.version == want.version == "", f"{artifact} {name} must be unversioned")
        if want.type == "OBJECT":
            require(have.size == want.size, f"{artifact} {name} size {have.size} differs from musl {want.size}")
        else:
            require(have.size > 0, f"{artifact} {name} has no code size")
    comparable = _singly_defined(candidate_rows) & _singly_defined(reference_rows)
    have_peers = storage_peers(candidate_rows, comparable)
    want_peers = storage_peers(reference_rows, comparable)
    for name in sorted(reference):
        have = have_peers.get(name, frozenset({name}))
        want = want_peers.get(name, frozenset({name}))
        require(
            have == want,
            f"{artifact} {name} shares storage with {sorted(have - {name})}; "
            f"musl shares it with {sorted(want - {name})}",
        )


def audit_static(
    roster: Roster,
    candidate_symbols: str,
    candidate_index: str,
    reference_symbols: str,
    reference_index: str,
) -> dict[str, object]:
    """Compare owned `libc.a` providers and extraction with musl `libc.a`."""
    candidate_rows = parse_symbols(candidate_symbols)
    reference_rows = parse_symbols(reference_symbols)
    candidate = providers(candidate_rows, roster.names, "owned libc.a")
    reference = providers(reference_rows, roster.names, "pinned musl libc.a")
    compare_providers(candidate, reference, candidate_rows, reference_rows, "owned libc.a")
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
        "capabilities": list(roster.capabilities),
        "names": len(candidate),
        "members": sorted({definition.member for definition in candidate.values()}),
        "aliases": _describe(alias_partition(candidate)),
    }


def audit_shared(
    roster: Roster,
    candidate_symbols: str,
    reference_symbols: str,
    reference_static_symbols: str,
) -> dict[str, object]:
    """Compare owned `libc.so` dynamic providers with musl `libc.so`.

    Candidate-only spellings have no musl dynamic row; they must be DEFAULT
    exports with musl's static type and binding, and share their entry point
    with exactly the spellings that share it in musl's `libc.a`.
    """
    shared_names = [name for name in roster.names if name not in roster.candidate_only]
    candidate_rows = parse_symbols(candidate_symbols)
    candidate = providers(candidate_rows, roster.names, "owned libc.so")
    reference_rows = parse_symbols(reference_symbols)
    exported = {row.name for row in reference_rows}
    for name in roster.candidate_only:
        require(name not in exported, f"pinned musl libc.so exports candidate-only {name}")
    reference = providers(reference_rows, shared_names, "pinned musl libc.so")
    compare_providers(candidate, reference, candidate_rows, reference_rows, "owned libc.so")
    static_rows = parse_symbols(reference_static_symbols)
    static_reference = providers(static_rows, sorted(roster.candidate_only), "pinned musl libc.a")
    comparable = _singly_defined(candidate_rows) & _singly_defined(static_rows)
    have_peers = storage_peers(candidate_rows, comparable)
    want_peers = storage_peers(static_rows, comparable)
    for name in sorted(roster.candidate_only):
        have, want = candidate[name], static_reference[name]
        require(have.type == want.type, f"owned libc.so {name} type {have.type} differs from musl {want.type}")
        require(
            have.binding == want.binding,
            f"owned libc.so {name} binding {have.binding} differs from musl {want.binding}",
        )
        require(have.visibility == "DEFAULT", f"owned libc.so must export candidate-only {name}")
        require(have.version == "", f"owned libc.so {name} must be unversioned")
        require(have.size > 0 or want.type == "OBJECT", f"owned libc.so {name} has no code size")
        require(
            have_peers.get(name) == want_peers.get(name),
            f"owned libc.so {name} shares storage with {sorted(have_peers.get(name, set()) - {name})}; "
            f"musl libc.a shares it with {sorted(want_peers.get(name, set()) - {name})}",
        )
    return {
        "capabilities": list(roster.capabilities),
        "names": len(candidate),
        "candidate_only": sorted(roster.candidate_only),
        "aliases": _describe(alias_partition(candidate)),
    }


def data_names(roster: Roster, reference_symbols: str) -> tuple[str, ...]:
    """Roster spellings that pinned musl `libc.so` defines as OBJECT."""
    return tuple(sorted(
        row.name for row in parse_symbols(reference_symbols)
        if row.name in roster.names and row.type == "OBJECT"
    ))


def audit_copy_executable(
    roster: Roster,
    executable_symbols: str,
    executable_relocations: str,
    library_symbols: str,
    reference_symbols: str,
    label: str,
) -> dict[str, object]:
    """Require executable COPY storage for every data spelling it reads.

    The non-PIE consumer names every musl data spelling of the roster. Each
    must be defined by the executable itself (the linker's copy, or an alias
    of a copy) and the executable's alias partition must equal the library's;
    at least one R_X86_64_COPY must carry each storage group.
    """
    objects = data_names(roster, reference_symbols)
    require(bool(objects), f"{label} roster has no musl data spellings to copy")
    executable = {
        row.name: row for row in parse_symbols(executable_symbols)
        if row.name in objects
    }
    library = providers(parse_symbols(library_symbols), objects, f"{label} libc.so")
    copies = parse_copy_relocations(executable_relocations)
    for name in objects:
        require(name in executable, f"{label} executable does not own COPY storage for {name}")
    have = alias_partition(executable)
    want = alias_partition(library)
    require(
        have == want,
        f"{label} executable COPY alias partition {_describe(have)} differs from libc.so {_describe(want)}",
    )
    for group in want:
        require(group & copies, f"{label} executable has no R_X86_64_COPY for {sorted(group)}")
    return {"copied": sorted(copies & set(objects)), "groups": len(want)}


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ProviderClosureError(f"cannot read {path}: {error}") from error


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--capability", action="append", required=True)
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
    shared.add_argument("reference_static_symbols")
    copy = commands.add_parser("copy")
    copy.add_argument("label")
    copy.add_argument("executable_symbols")
    copy.add_argument("executable_relocations")
    copy.add_argument("library_symbols")
    copy.add_argument("reference_symbols")
    options = parser.parse_args(arguments)

    roster = frozen_roster(options.capability)
    if options.command == "roster":
        report: object = list(roster.names)
    elif options.command == "static":
        report = audit_static(
            roster,
            _read(options.candidate_symbols), _read(options.candidate_index),
            _read(options.reference_symbols), _read(options.reference_index),
        )
    elif options.command == "shared":
        report = audit_shared(
            roster, _read(options.candidate_symbols), _read(options.reference_symbols),
            _read(options.reference_static_symbols),
        )
    else:
        report = audit_copy_executable(
            roster, _read(options.executable_symbols), _read(options.executable_relocations),
            _read(options.library_symbols), _read(options.reference_symbols), options.label,
        )
    json.dump(report, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProviderClosureError as error:
        raise SystemExit(f"x86 C-ABI provider closure: {error}") from error
