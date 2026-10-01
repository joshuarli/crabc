#!/usr/bin/env python3
"""Pinned C/Rust native x86-64 arena reservation and slice-lifecycle differential.

`m2_arena_lifecycle_x86_64.c` drives the unchanged pinned `src/arena.c`
reservation, registry search, slice claim, and release routines through
`static.c`; `arena::owned::tests::emit_native_arena_lifecycle_trace` drives the
Rust `ProcessArenaBacking` entries for the same scenarios. Both emit the same
ordered, address-free `m2.arena.lifecycle.N=V` fields, and every field must
match, except that scenario 23's default-option reservations carry the
recorded `CRABC-MI-ARENA-RESERVATION-NO-THP` advice (`expected_rust`). The aggregate `allocator-m2` gate calls `run_evidence` with its one
prebuilt test binary; `allocator-m2-arena-lifecycle` runs `main` for focused
development without producing an aggregate receipt.

The differential covers arena creation, OS reservation, and caller-owned
external callback commitment/purge, refusal/retry, bitmap transitions, registry
retirement, and caller release. Real private managed arenas additionally cover
small, medium, and large regular-page abandonment, a foreign held-owner claim
refusal with bitmap/count restoration, retry and same-owner reassociation,
foreign remote-free publication, owner collection, and terminal span/map release.
The cross-thread caller additionally exercises natural owner exit, a distinct
replacement owner, held-claim restoration, reassociation, and terminal page
release. Hardware memory policy remains a separate condition.

The optional ambient observation authenticates Rust's self-contained musl
1.2.5 separately from the pinned allocator oracle. It records current mallocng
active-list ownership and completely free bouncing groups; historical allocation
stacks and previous-cycle pool membership cannot explain a current mapping.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
from typing import Any, Mapping, Sequence


FIXTURE = Path(__file__).with_suffix(".c").resolve()
CHECK_ID = "arena-reservation-lifecycle-c-rust-differential"
TARGET = "arena::owned::tests::emit_native_arena_lifecycle_trace"
RETENTION_TARGET = "dynamic_theap::tests::x86_64_cross_thread_arena_retention_trace"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
# Rust's self-contained ambient libc differs from the pinned allocator oracle.
AMBIENT_LIBC_SHA256 = "e699c64b0c6b427d89ad5bf767bf78beb30c19930c5dedff635951636e8f9f70"
PROFILE_FEATURES = {"release": [], "debug-1": ["mi-debug-1", "mi-stat-1", "mi-stat-2"],
                    "stat-1": ["mi-stat-1"], "stat-2": ["mi-stat-1", "mi-stat-2"]}
FIELD = re.compile(r"m2\.arena\.lifecycle\.([0-9]+)=(-?[0-9]+)")
# libtest's `--nocapture` output places the first field after this delimiter.
RUST_INLINE_PREFIX = f"test {TARGET} ... "
# Scenario markers are `-1000 - scenario`; the final marker is scenario 26.
FINAL_MARKER = -1026
THP_SCENARIO = -1023
# Scenario 23 cells: this sentinel, allow_thp, eager commit, advised, last
# advice, and whether every advice call carried it.
THP_CELL = -2300
MADV_NOHUGEPAGE = 15


def parse_trace(output: str, *, source: str) -> list[int]:
    """Return the complete ordered field list, rejecting gaps and stray text."""

    values: list[int] = []
    for line in output.splitlines():
        if line.startswith(RUST_INLINE_PREFIX):
            line = line[len(RUST_INLINE_PREFIX):]
        if "m2.arena.lifecycle." not in line:
            continue
        match = FIELD.fullmatch(line)
        if match is None or int(match.group(1)) != len(values):
            raise ValueError(f"{source} arena lifecycle trace has a malformed or out-of-order field: {line!r}")
        values.append(int(match.group(2)))
    if not values or values[0] != -1001 or values[-1] != FINAL_MARKER:
        raise ValueError(f"{source} arena lifecycle trace is incomplete")
    return values


def parse_retention(output: str, *, source: str, last_cycle: int = 32) -> list[dict[str, int]]:
    """Keep each warmed-baseline and post-teardown mapping snapshot exact."""
    fields = []
    prefix = f"test {RETENTION_TARGET} ... "
    for line in output.splitlines():
        line = line.removeprefix(prefix)
        if "m2.arena.retention." not in line:
            continue
        if line.startswith(tuple(f"m2.arena.retention.{kind}." for kind in ("root", "child", "map", "maps"))):
            continue
        match = re.fullmatch(r"m2\.arena\.retention\.([0-9]+)\.(ranges|bytes)=([0-9]+)", line)
        if match is None:
            raise ValueError(f"{source} retention snapshot malformed")
        fields.append((int(match[1]), match[2], int(match[3])))
    roster = [(cycle, kind) for cycle in range(last_cycle + 1) for kind in ("ranges", "bytes")]
    if [(cycle, kind) for cycle, kind, _ in fields] != roster or any(value <= 0 for _, _, value in fields):
        raise ValueError(f"{source} retention snapshots incomplete or out of order")
    return [{"ranges": fields[cycle*2][2], "bytes": fields[cycle*2+1][2]} for cycle in range(last_cycle + 1)]


def retention_interval_union(intervals: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """Normalize live mapping observations without counting overlapping VMAs twice."""
    ordered = sorted(intervals)
    result: list[tuple[int, int]] = []
    for start, end in ordered:
        if start < 0 or end <= start:
            raise ValueError("retention interval is empty or reversed")
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def _retention_overlap(left: Sequence[tuple[int, int]], right: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    a = retention_interval_union(left)
    b = retention_interval_union(right)
    i = j = 0
    result = []
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if hi > lo:
            result.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return result


def _retention_intersection(left: Sequence[tuple[int, int]], right: Sequence[tuple[int, int]]) -> int:
    return sum(end-start for start, end in _retention_overlap(left, right))


def classify_retention_intervals(before: Sequence[tuple[int, int]], after: Sequence[tuple[int, int]],
                                 roots: Sequence[tuple[int, int]]) -> dict[str, int]:
    """Expose growth outside observed metadata and process-wide PageMap extents."""
    old = retention_interval_union(before)
    new = retention_interval_union(after)
    witnesses = retention_interval_union(roots)
    common = _retention_intersection(old, new)
    added = sum(end-start for start, end in new) - common
    removed = sum(end-start for start, end in old) - common
    # A root overlapping the warmed baseline explains no newly mapped byte.
    covered = _retention_overlap(new, witnesses)
    attributed = sum(end-start for start, end in retention_interval_union(covered)) - _retention_intersection(covered, old)
    return {"added_bytes": added, "removed_bytes": removed,
            "attributed_bytes": attributed, "unexplained_bytes": added-attributed}


def parse_retention_attribution(output: str, *, source: str, last_cycle: int = 32) -> list[dict[str, Any]]:
    """Require every child and mapping observation before attributing virtual growth."""
    roots: dict[tuple[int, int], list[tuple[str, int, int, int]]] = {}
    children: dict[tuple[int, int], int] = {}
    maps: dict[int, list[tuple[int, int]]] = {}
    map_counts: dict[int, int] = {}
    prefix = f"test {RETENTION_TARGET} ... "
    for line in output.splitlines():
        line = line.removeprefix(prefix)
        if not line.startswith("m2.arena.retention."):
            continue
        root = re.fullmatch(r"m2\.arena\.retention\.root\.([0-9]+)\.([0-9]+)\.([0-9]+)\.(os-page|os-arena|external-arena|external-raw|process-pagemap|process-metadata)=([0-9]+),([0-9]+),([0-9]+)", line)
        child = re.fullmatch(r"m2\.arena\.retention\.child\.([0-9]+)\.([0-9]+)=([0-9]+)", line)
        mapping = re.fullmatch(r"m2\.arena\.retention\.map\.([0-9]+)\.([0-9]+)=([0-9]+),([0-9]+)", line)
        count = re.fullmatch(r"m2\.arena\.retention\.maps\.([0-9]+)=([0-9]+)", line)
        if root:
            cycle, member, index = map(int, root.group(1, 2, 3))
            category = root[4]
            start, end, coverage = map(int, root.group(5, 6, 7))
            key = (cycle, member)
            entries = roots.setdefault(key, [])
            value = (category, start, end, coverage)
            if index != len(entries) or end <= start or coverage > end-start or any(value[:3] == existing[:3] for existing in entries) or key in children:
                raise ValueError(f"{source} root observation malformed or duplicated")
            if category == "external-raw" and coverage != 0:
                raise ValueError(f"{source} caller external mapping survived its explicit unmap")
            entries.append(value)
        elif child:
            cycle, member, value = map(int, child.groups())
            key = (cycle, member)
            if key in children or value != len(roots.get(key, [])) or value == 0:
                raise ValueError(f"{source} child root roster incomplete or duplicated")
            if sum(root[0] == "external-raw" for root in roots[key]) != 1:
                raise ValueError(f"{source} child caller mapping observation missing")
            children[key] = value
        elif mapping:
            cycle, index, start, end = map(int, mapping.groups())
            entries = maps.setdefault(cycle, [])
            if index != len(entries) or end <= start or (entries and start < entries[-1][1]) or cycle in map_counts:
                raise ValueError(f"{source} mapping observation malformed or duplicated")
            entries.append((start, end))
        elif count:
            cycle, value = map(int, count.groups())
            if cycle in map_counts or value != len(maps.get(cycle, [])) or value == 0:
                raise ValueError(f"{source} mapping roster incomplete or duplicated")
            map_counts[cycle] = value
        elif not re.fullmatch(r"m2\.arena\.retention\.[0-9]+\.(ranges|bytes)=[0-9]+", line):
            raise ValueError(f"{source} unknown retention observation")
    if set(children) != {(cycle, child) for cycle in range(last_cycle + 1) for child in range(6)} or set(map_counts) != set(range(last_cycle + 1)) or set(roots) != set(children) or set(maps) != set(map_counts):
        raise ValueError(f"{source} retention attribution population incomplete")
    result = []
    cumulative = []
    for cycle in range(last_cycle + 1):
        for child in range(6):
            cumulative.extend((start, end) for category, start, end, covered in roots[cycle, child]
                              if category in ("os-page", "process-pagemap") and covered == end-start)
        # Parent metadata pages can be reclaimed during later allocations;
        # only the last child's current owner observation supports this snapshot.
        current_metadata = [(start, end) for category, start, end, covered in roots[cycle, 5]
                            if category == "process-metadata" and covered == end-start]
        result.append({"maps": maps[cycle], "children": [roots[cycle, child] for child in range(6)],
                       "classification": classify_retention_intervals(maps[0], maps[cycle], cumulative + current_metadata)})
    return result


def parse_attributed_retention(output: str, *, source: str, last_cycle: int = 32) -> list[dict[str, Any]]:
    """Bind aggregate snapshots to the same complete observed interval population."""
    snapshots = parse_retention(output, source=source, last_cycle=last_cycle)
    observations = parse_retention_attribution(output, source=source, last_cycle=last_cycle)
    for snapshot, observation in zip(snapshots, observations):
        mappings = observation["maps"]
        if snapshot["ranges"] != len(mappings) or snapshot["bytes"] != sum(end-start for start, end in mappings):
            raise ValueError(f"{source} aggregate retention snapshot differs from observed mappings")
        snapshot.update(observation)
    return snapshots


def parse_retention_geometry(output: str, snapshots: Sequence[Mapping[str, Any]], *, arena_reserve: int, source: str) -> dict[str, Any]:
    """Bind a finite PageMap storage ceiling to its actual mapped root roster."""
    lines = [line for line in output.splitlines() if line.startswith("source_root_bound ")]
    if len(lines) != 1:
        raise ValueError(f"{source} PageMap geometry observation missing or duplicated")
    pairs = re.findall(r"([a-z_]+)=([0-9]+)", lines[0])
    fields = {key: int(value) for key, value in pairs}
    required = {"arena_reserve_kib", "pagemap_slots", "submap_bytes", "maximum_pagemap_bytes"}
    if len(fields) != len(pairs) or set(fields) not in (required | {"pagemap_root_bytes"}, required | {"pagemap_reserved_bytes"}) or fields["arena_reserve_kib"] != arena_reserve:
        raise ValueError(f"{source} PageMap geometry policy or fields differ")
    slots, submap = fields["pagemap_slots"], fields["submap_bytes"]
    if slots < 1 or submap != 65536:
        raise ValueError(f"{source} PageMap storage geometry differs")
    root_extent = None
    observed = []
    for snapshot in snapshots:
        current = []
        for child in snapshot["children"]:
            extents = [(start, end) for category, start, end, covered in child if category == "process-pagemap" and covered == end-start]
            if not extents:
                raise ValueError(f"{source} PageMap owner root missing")
            if root_extent is None:
                root_extent = extents[0]
            if extents[0] != root_extent or len(extents) > slots or any(end-start != submap for start, end in extents[1:]):
                raise ValueError(f"{source} PageMap source roster exceeds or differs from storage geometry")
            total = sum(end-start for start, end in extents)
            if total != sum(end-start for start, end in retention_interval_union(extents)):
                raise ValueError(f"{source} PageMap storage extents overlap")
            current.append(total)
        observed.append(max(current))
    if root_extent is None:
        raise ValueError(f"{source} PageMap observation empty")
    root_bytes = root_extent[1]-root_extent[0]
    if fields.get("pagemap_root_bytes", root_bytes) != root_bytes or fields.get("pagemap_reserved_bytes", root_bytes) > root_bytes or fields["maximum_pagemap_bytes"] != root_bytes + (slots-1)*submap:
        raise ValueError(f"{source} PageMap ceiling differs from actual root extent")
    return {**fields, "pagemap_root_bytes": root_bytes, "observed_pagemap_bytes": observed}


def parse_ambient_retention(output: str, snapshots: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Admit current circular pool membership; never carry old groups forward."""
    groups: dict[int, list[tuple[int, ...]]] = {}
    counts: dict[int, int] = {}
    for line in output.splitlines():
        if not line.startswith("m2.arena.ambient."):
            continue
        group = re.fullmatch(r"m2\.arena\.ambient\.group\.([0-9]+)\.([0-9]+)=([0-9]+(?:,[0-9]+){11})", line)
        count = re.fullmatch(r"m2\.arena\.ambient\.groups\.([0-9]+)=([0-9]+)", line)
        if group:
            cycle, index = map(int, group.group(1, 2))
            entries = groups.setdefault(cycle, [])
            fields = tuple(map(int, group[3].split(",")))
            sc, meta, prev, next_, start, end, avail, freed, last, freeable, bounce, usage = fields
            if (cycle in counts or index != len(entries) or index >= 1024 or sc >= 48
                    or meta == 0 or meta % 8 or prev == 0 or next_ == 0 or start == 0 or start % 16
                    or end < start or (end > start and (start % 4096 or (end-start) % 4096))
                    or last > 31 or freeable > 1 or bounce > 150 or usage < last+1
                    or (not 7 <= sc < 39 and bounce != 0)
                    or (avail | freed) & ~((2 << last)-1) or avail & freed
                    or any(entry[1] == meta for entry in entries)):
                raise ValueError("ambient pool group malformed or duplicated")
            entries.append(fields)
        elif count:
            cycle, value = map(int, count.groups())
            if cycle in counts or value != len(groups.get(cycle, [])):
                raise ValueError("ambient pool roster incomplete or duplicated")
            counts[cycle] = value
        else:
            raise ValueError("unknown ambient pool observation")
    if set(counts) != set(range(len(snapshots))):
        raise ValueError("ambient pool snapshots incomplete")
    result = []
    for cycle, snapshot in enumerate(snapshots):
        entries = groups.get(cycle, [])
        by_meta = {entry[1]: entry for entry in entries}
        for sc in {entry[0] for entry in entries}:
            members = [entry for entry in entries if entry[0] == sc]
            visited = set()
            meta = members[0][1]
            while meta not in visited:
                if meta not in by_meta or by_meta[meta][0] != sc:
                    raise ValueError("ambient pool list leaves its size class")
                visited.add(meta)
                meta = by_meta[meta][3]
            if meta != members[0][1] or len(visited) != len(members):
                raise ValueError("ambient pool class has disconnected circular lists")
            if any(entry[10:] != members[0][10:] for entry in members):
                raise ValueError("ambient class counters inconsistent")
        extents = []
        empty_bouncing = []
        for entry in entries:
            sc, meta, prev, next_, start, end, avail, freed, last, freeable, bounce, usage = entry
            if (prev not in by_meta or next_ not in by_meta or by_meta[prev][3] != meta
                    or by_meta[next_][2] != meta or by_meta[prev][0] != sc or by_meta[next_][0] != sc):
                raise ValueError("ambient pool circular membership inconsistent")
            if end == start:
                continue  # Nested groups own a slot, not an independent mapping.
            if _retention_intersection([(start, end)], snapshot["maps"]) != end-start:
                raise ValueError("live ambient pool extent is not completely mapped")
            extents.append((start, end))
            # Multi-slot groups use the class stride exactly. Singleton groups
            # also need a stride suitability check and are not labeled here.
            if (last > 0 and (avail | freed) == (2 << last)-1 and freeable and prev == next_ == meta
                    and bounce >= 100 and not (9*(last+1) <= usage and last+1 < 20)):
                empty_bouncing.append((start, end))
        result.append({"groups": entries, "mapped_extents": extents,
                       "empty_bouncing_extents": empty_bouncing,
                       "classification": classify_retention_intervals(snapshots[0]["maps"], snapshot["maps"], extents)})
    return result


def authenticate_ambient_pool(harness: Any, binary: Path) -> dict[str, Any]:
    """Bind private-layout reads to the exact ambient archive and linked code."""
    library_dir = Path(harness.rust_target_self_contained_native_library_search_path(
        "x86_64-unknown-linux-musl", "libc.a"))
    archive = (library_dir / "libc.a").read_bytes()
    if hashlib.sha256(archive).hexdigest() != AMBIENT_LIBC_SHA256:
        raise ValueError("ambient musl 1.2.5 archive identity differs")
    members = {}
    if archive[:8] != b"!<arch>\n":
        raise ValueError("ambient archive malformed")
    pos = 8
    while pos < len(archive):
        header = archive[pos:pos+60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("ambient archive member malformed")
        length = int(header[48:58])
        name = header[:16].decode("ascii").strip().removesuffix("/")
        members[name] = archive[pos+60:pos+60+length]
        pos += 60 + length + length % 2

    def elf(data):
        if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
            raise ValueError("ambient product is not little-endian x86-64 ELF")
        offset = struct.unpack_from("<Q", data, 40)[0]
        size, count = struct.unpack_from("<HH", data, 58)
        if size != 64:
            raise ValueError("ambient ELF section layout differs")
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset+i*size) for i in range(count)]
        def section_bytes(index):
            s = sections[index]
            return data[s[4]:s[4]+s[5]]
        symbols = {}
        for index, section in enumerate(sections):
            if section[1] != 2:
                continue
            strings = section_bytes(section[6])
            table = section_bytes(index)
            for pos in range(0, len(table), 24):
                name, info, other, index_, value, length = struct.unpack_from("<IBBHQQ", table, pos)
                if 0 < index_ < len(sections) and length:
                    symbols[strings[name:strings.index(b"\0", name)].decode()] = (index_, value, length)
        def symbol(name):
            index, value, length = symbols[name]
            start = value-sections[index][3]
            return bytearray(section_bytes(index)[start:start+length]), index, start
        return sections, section_bytes, symbols, symbol

    _, _, linked_symbols, linked_symbol = elf(binary.read_bytes())
    if linked_symbols["__malloc_context"][2] != 928:
        raise ValueError("ambient context ABI differs")
    proofs = []
    for member, names in (("malloc.lo", ("alloc_slot", "__libc_malloc_impl", "__malloc_alloc_meta", "__malloc_atfork")),
                          ("free.lo", ("nontrivial_free", "__libc_free"))):
        sections, section_bytes, _, symbol = elf(members[member])
        for name in names:
            before, index, start = symbol(name)
            after, _, _ = linked_symbol(name)
            if len(before) != len(after):
                raise ValueError(f"linked ambient function length differs: {name}")
            for section_index, section in enumerate(sections):
                if section[1] != 4 or section[7] != index:
                    continue
                table = section_bytes(section_index)
                for pos in range(0, len(table), 24):
                    where, info, addend = struct.unpack_from("<QQq", table, pos)
                    if start <= where < start+len(before):
                        width = {1: 8, 2: 4, 4: 4}.get(info & 0xffffffff)
                        if width is None or where-start+width > len(before):
                            raise ValueError("ambient function relocation unsupported")
                        before[where-start:where-start+width] = bytes(width)
                        after[where-start:where-start+width] = bytes(width)
            if before != after:
                raise ValueError(f"linked ambient function bytes differ: {name}")
            proofs.append({"name": name, "length": len(before), "normalized_sha256": hashlib.sha256(before).hexdigest()})
    return {"ambient_musl_version": "1.2.5", "archive_sha256": AMBIENT_LIBC_SHA256,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "functions": proofs}


def expected_rust(c_trace: list[int]) -> list[int]:
    """The pinned C trace with the one recorded divergence applied.

    At the
    default allow_thp=1 without large OS pages, a Rust arena reservation is
    advised MADV_NOHUGEPAGE where pinned C advises MADV_HUGEPAGE or nothing.
    Only scenario 23's advice records change; every other field, including
    the allow_thp=0 and allow_thp=2 cells, must equal pinned C.
    """

    expected = list(c_trace)
    start = expected.index(THP_SCENARIO)
    for index in range(start, expected.index(FINAL_MARKER)):
        if expected[index] == THP_CELL and expected[index + 1] == 1:
            expected[index + 3:index + 6] = [1, MADV_NOHUGEPAGE, 1]
    return expected


def compare(c_trace: list[int], rust_trace: list[int]) -> dict[str, Any]:
    """Require field-for-field equality with the recorded divergence and name the first differences."""

    c_trace = expected_rust(c_trace)
    if c_trace == rust_trace:
        return {"compared_value_count": len(c_trace), "status": "matched"}
    mismatches = [
        f"{index}: C={c}, Rust={r}"
        for index, (c, r) in enumerate(zip(c_trace, rust_trace))
        if c != r
    ][:16]
    if len(c_trace) != len(rust_trace):
        mismatches.append(f"field count: C={len(c_trace)}, Rust={len(rust_trace)}")
    raise ValueError("native x86 arena lifecycle differs from pinned C: " + "; ".join(mismatches))


def retention_environment(arena_reserve: int | None) -> dict[str, str]:
    """Select an explicit retention policy without ambient option inheritance."""
    environment = dict(os.environ)
    environment.pop("CRABC_MI_RETENTION_ARENA_RESERVE_KIB", None)
    if arena_reserve is not None:
        if not 0 <= arena_reserve <= 1048576:
            raise ValueError("retention arena reservation must be between 0 and 1048576 KiB")
        environment["CRABC_MI_RETENTION_ARENA_RESERVE_KIB"] = str(arena_reserve)
    return environment


def run_oracle(harness: Any, *, offline: bool, profile: str = "release", repeat_retention: bool = False, last_cycle: int = 32, arena_reserve: int | None = None) -> tuple[list[str], Any]:
    """Build the fixture against the pinned archive and return its trace."""

    if profile not in PROFILES:
        raise harness.HarnessError("unsupported arena lifecycle configuration")
    import x86_64_m4_gate as profiles

    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
    if profile != "release":
        artifacts /= profile
    artifacts.mkdir(parents=True, exist_ok=True)
    if repeat_retention:
        artifacts /= "retention"
        if last_cycle != 32:
            artifacts /= f"last-cycle-{last_cycle}"
        if arena_reserve is not None:
            artifacts /= f"arena-reserve-{arena_reserve}"
        artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "oracle"
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-arena-lifecycle-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *(harness.CONFIGURATION_PROFILES["release"] if profile == "release"
              else profiles.api_profile_flags(profile)),
            # The fixture includes `static.c`, the single pinned translation unit.
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=mprotect", "-Wl,--wrap=madvise", "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.write_json(artifacts / "c-build.json", build)
        harness.require_success(build, "pinned C native x86 arena lifecycle oracle build")
        options = (["--source-root-bound", str(last_cycle)] if last_cycle != 32 else ["--repeat-retention"]) if repeat_retention else []
        run = harness.command_record([str(binary)] + options, cwd=source, env=retention_environment(arena_reserve if repeat_retention else None), timeout_seconds=180)
        harness.write_json(artifacts / "c-execute.json", run)
        (artifacts / "c.log").write_text(str(run["stdout"]), encoding="utf-8")
        harness.require_success(run, "pinned C native x86 arena lifecycle oracle")
    (artifacts / "c.log").write_text(str(run["stdout"]), encoding="utf-8")
    rows = (parse_attributed_retention(str(run["stdout"]), source="pinned C", last_cycle=last_cycle) if repeat_retention
            else parse_trace(str(run["stdout"]), source="pinned C"))
    if repeat_retention and arena_reserve is not None:
        geometry = parse_retention_geometry(str(run["stdout"]) + "\n" + str(run["stderr"]), rows,
                                            arena_reserve=arena_reserve, source="pinned C")
        harness.write_json(artifacts / "c-pagemap-geometry.json", geometry)
    return command, rows


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the differential against the aggregate gate's prebuilt test binary."""

    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 arena lifecycle check changed")
    try:
        c_command, c_trace = run_oracle(harness, offline=offline)
        rust, rust_output = harness._x86_64_run_exact_program_check(
            test_program, check, nocapture=True, gate_name="native x86 M2 arena lifecycle",
        )
        comparison = compare(c_trace, parse_trace(rust_output, source="Rust"))
    except ValueError as error:
        raise harness.HarnessError(str(error)) from error
    evidence = {
        "c_command": c_command,
        "comparison": comparison,
        "fixture": harness.artifact_record(FIXTURE),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "status": "passed",
        "trace_sha256": hashlib.sha256(
            json.dumps(c_trace, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    harness.write_json(harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle/evidence.json", evidence)
    return evidence


def native_program(harness: Any, profile: str, artifacts: Path) -> dict[str, Any]:
    """Build and retain the matching Cargo-emitted native test executable."""
    if profile not in PROFILES:
        raise harness.HarnessError("unsupported arena lifecycle configuration")
    manifest = harness.ROOT / "crabc-mimalloc/Cargo.toml"
    command = [harness.require_tool("cargo"), "test", "--manifest-path", str(manifest),
               "--locked", "--offline", "--target", "x86_64-unknown-linux-musl",
               "--lib", "--no-default-features"]
    if profile != "release":
        command.extend(("--features", "mi-" + profile))
    command.extend(("--no-run", "--message-format=json"))
    build = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=3600)
    harness.write_json(artifacts / "rust-build.json", build)
    harness.require_success(build, "native arena lifecycle test product build")
    candidates = []
    for line in str(build["stdout"]).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (isinstance(event, Mapping) and event.get("reason") == "compiler-artifact"
                and event.get("manifest_path") == str(manifest)
                and event.get("target", {}).get("name") == "crabc_mimalloc"
                and event.get("target", {}).get("src_path") == str(manifest.parent / "src/lib.rs")
                and event.get("target", {}).get("kind") == ["lib"]
                and event.get("profile", {}).get("test") is True
                and event.get("features") == PROFILE_FEATURES[profile]
                and isinstance(event.get("executable"), str)):
            candidates.append(event)
    if len(candidates) != 1 or not Path(candidates[0]["executable"]).is_file():
        raise harness.HarnessError("native arena lifecycle compiler executable authority differs")
    import shutil
    binary = artifacts / "native-program"
    shutil.copy2(candidates[0]["executable"], binary)
    harness.write_json(artifacts / "compiler-artifact.json", candidates[0])
    return {"path": binary, "execution": {"test_threads": 1, "timeout_seconds": 180}}


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=(*PROFILES, "all"), default="release")
    parser.add_argument("--repeat-retention", action="store_true", help="report 32 post-warmup child cycles; does not qualify bounded memory")
    parser.add_argument("--observe-ambient-pool", action="store_true", help="authenticate and observe the live ambient musl 1.2.5 pool")
    parser.add_argument("--retention-last-cycle", type=int, default=32, help="opt-in extended source-root observation, between 32 and 128; growth remains unbounded unless separately proved")
    parser.add_argument("--retention-arena-reserve", type=int, default=None, help="retention-only ArenaReserve in KiB, 0 through source default 1048576; unset preserves zero")
    arguments = parser.parse_args(arguments)
    if arguments.observe_ambient_pool and not arguments.repeat_retention:
        parser.error("--observe-ambient-pool requires --repeat-retention")
    if not 32 <= arguments.retention_last_cycle <= 128 or (arguments.retention_last_cycle != 32 and not arguments.repeat_retention):
        parser.error("--retention-last-cycle requires --repeat-retention and a value between 32 and 128")
    if arguments.retention_arena_reserve is not None and (not arguments.repeat_retention or not 0 <= arguments.retention_arena_reserve <= 1048576):
        parser.error("--retention-arena-reserve requires --repeat-retention and a value between 0 and 1048576 KiB")
    import run as harness  # this script's directory is first on sys.path

    harness.require_native_x86_64()
    status = 0
    for profile in (PROFILES if arguments.profile == "all" else (arguments.profile,)):
        artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
        if profile != "release":
            artifacts /= profile
        if arguments.repeat_retention:
            artifacts /= "retention"
            if arguments.retention_last_cycle != 32:
                artifacts /= f"last-cycle-{arguments.retention_last_cycle}"
            if arguments.retention_arena_reserve is not None:
                artifacts /= f"arena-reserve-{arguments.retention_arena_reserve}"
        artifacts.mkdir(parents=True, exist_ok=True)
        try:
            _, c_trace = run_oracle(harness, offline=True, profile=profile,
                                   **({"repeat_retention": True} if arguments.repeat_retention else {}),
                                   **({"last_cycle": arguments.retention_last_cycle} if arguments.retention_last_cycle != 32 else {}),
                                   **({"arena_reserve": arguments.retention_arena_reserve} if arguments.retention_arena_reserve is not None else {}))
            program = native_program(harness, profile, artifacts)
            environment = retention_environment(arguments.retention_arena_reserve)
            if arguments.retention_last_cycle != 32:
                environment = {**environment, "CRABC_MI_RETENTION_LAST_CYCLE": str(arguments.retention_last_cycle)}
            if arguments.observe_ambient_pool:
                try:
                    proof = authenticate_ambient_pool(harness, Path(program["path"]))
                except (KeyError, IndexError, struct.error, UnicodeDecodeError) as error:
                    raise ValueError("ambient linked product or archive structure differs") from error
                harness.write_json(artifacts / "ambient-libc-authentication.json", proof)
                environment = {**(environment or os.environ), "CRABC_MI_AUTHENTICATED_AMBIENT_POOL": "1"}
            command = harness._x86_64_program_check_command(
                program, RETENTION_TARGET if arguments.repeat_retention else TARGET, nocapture=True, gate_name="native arena lifecycle")
            rust = harness.command_record(command, cwd=harness.ROOT, env=environment, timeout_seconds=180)
            harness.write_json(artifacts / "rust-execute.json", rust)
            (artifacts / "rust.log").write_text(str(rust["stdout"]) + str(rust["stderr"]), encoding="utf-8")
            harness.require_success(rust, "native arena lifecycle trace")
            output = str(rust["stdout"]) + "\n" + str(rust["stderr"])
            if harness.parse_rust_test_count(output) != 1:
                raise harness.HarnessError("exact arena lifecycle selection did not execute one passing test")
            if arguments.repeat_retention:
                native_rows = parse_attributed_retention(output, source="Rust", last_cycle=arguments.retention_last_cycle)
                if arguments.retention_arena_reserve is not None:
                    geometry = parse_retention_geometry(output, native_rows, arena_reserve=arguments.retention_arena_reserve, source="Rust")
                    harness.write_json(artifacts / "rust-pagemap-geometry.json", geometry)
                if arguments.observe_ambient_pool:
                    ambient = parse_ambient_retention(output, native_rows)
                    harness.write_json(artifacts / "ambient-pool-observation.json", ambient)
                    print(f"arena retention {profile} ambient musl 1.2.5: current live pool classification {ambient[-1]['classification']}; empty bouncing extents {ambient[-1]['empty_bouncing_extents']}")
                for label, rows in (("C", c_trace), ("native", native_rows)):
                    print(f"arena retention {profile} {label}: ranges {rows[0]['ranges']}->{rows[-1]['ranges']}; bytes {rows[0]['bytes']}->{rows[-1]['bytes']}; source-root classification {rows[-1]['classification']}; exact raw snapshots {artifacts}")
                continue
            comparison = compare(c_trace, parse_trace(output, source="Rust"))
        except (ValueError, harness.HarnessError) as error:
            print(f"ERROR: {profile}: {error}", file=sys.stderr)
            status = 1
            continue
        print(f"arena lifecycle {profile}: pinned C/Rust matched {comparison['compared_value_count']} fields; {artifacts}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
