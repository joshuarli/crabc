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
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


FIXTURE = Path(__file__).with_suffix(".c").resolve()
CHECK_ID = "arena-reservation-lifecycle-c-rust-differential"
TARGET = "arena::owned::tests::emit_native_arena_lifecycle_trace"
RETENTION_TARGET = "dynamic_theap::tests::x86_64_cross_thread_arena_retention_trace"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
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


def parse_retention(output: str, *, source: str) -> list[dict[str, int]]:
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
    roster = [(cycle, kind) for cycle in range(33) for kind in ("ranges", "bytes")]
    if [(cycle, kind) for cycle, kind, _ in fields] != roster or any(value <= 0 for _, _, value in fields):
        raise ValueError(f"{source} retention snapshots incomplete or out of order")
    return [{"ranges": fields[cycle*2][2], "bytes": fields[cycle*2+1][2]} for cycle in range(33)]


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


def parse_retention_attribution(output: str, *, source: str) -> list[dict[str, Any]]:
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
        root = re.fullmatch(r"m2\.arena\.retention\.root\.([0-9]+)\.([0-9]+)\.([0-9]+)\.(os-page|os-arena|external-arena|external-raw|process-pagemap)=([0-9]+),([0-9]+),([0-9]+)", line)
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
    if set(children) != {(cycle, child) for cycle in range(33) for child in range(6)} or set(map_counts) != set(range(33)) or set(roots) != set(children) or set(maps) != set(map_counts):
        raise ValueError(f"{source} retention attribution population incomplete")
    result = []
    cumulative = []
    for cycle in range(33):
        for child in range(6):
            cumulative.extend((start, end) for category, start, end, covered in roots[cycle, child]
                              if category in ("os-page", "process-pagemap") and covered == end-start)
        result.append({"maps": maps[cycle], "children": [roots[cycle, child] for child in range(6)],
                       "classification": classify_retention_intervals(maps[0], maps[cycle], cumulative)})
    return result


def parse_attributed_retention(output: str, *, source: str) -> list[dict[str, Any]]:
    """Bind aggregate snapshots to the same complete observed interval population."""
    snapshots = parse_retention(output, source=source)
    observations = parse_retention_attribution(output, source=source)
    for snapshot, observation in zip(snapshots, observations):
        mappings = observation["maps"]
        if snapshot["ranges"] != len(mappings) or snapshot["bytes"] != sum(end-start for start, end in mappings):
            raise ValueError(f"{source} aggregate retention snapshot differs from observed mappings")
        snapshot.update(observation)
    return snapshots


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


def run_oracle(harness: Any, *, offline: bool, profile: str = "release", repeat_retention: bool = False) -> tuple[list[str], Any]:
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
        run = harness.command_record([str(binary)] + (["--repeat-retention"] if repeat_retention else []), cwd=source, timeout_seconds=180)
        harness.write_json(artifacts / "c-execute.json", run)
        (artifacts / "c.log").write_text(str(run["stdout"]), encoding="utf-8")
        harness.require_success(run, "pinned C native x86 arena lifecycle oracle")
    (artifacts / "c.log").write_text(str(run["stdout"]), encoding="utf-8")
    return command, (parse_attributed_retention(str(run["stdout"]), source="pinned C") if repeat_retention
                     else parse_trace(str(run["stdout"]), source="pinned C"))


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
    arguments = parser.parse_args(arguments)
    import run as harness  # this script's directory is first on sys.path

    harness.require_native_x86_64()
    status = 0
    for profile in (PROFILES if arguments.profile == "all" else (arguments.profile,)):
        artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-arena-lifecycle"
        if profile != "release":
            artifacts /= profile
        if arguments.repeat_retention:
            artifacts /= "retention"
        artifacts.mkdir(parents=True, exist_ok=True)
        try:
            _, c_trace = run_oracle(harness, offline=True, profile=profile,
                                   **({"repeat_retention": True} if arguments.repeat_retention else {}))
            program = native_program(harness, profile, artifacts)
            command = harness._x86_64_program_check_command(
                program, RETENTION_TARGET if arguments.repeat_retention else TARGET, nocapture=True, gate_name="native arena lifecycle")
            rust = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=180)
            harness.write_json(artifacts / "rust-execute.json", rust)
            (artifacts / "rust.log").write_text(str(rust["stdout"]) + str(rust["stderr"]), encoding="utf-8")
            harness.require_success(rust, "native arena lifecycle trace")
            output = str(rust["stdout"]) + "\n" + str(rust["stderr"])
            if harness.parse_rust_test_count(output) != 1:
                raise harness.HarnessError("exact arena lifecycle selection did not execute one passing test")
            if arguments.repeat_retention:
                native_rows = parse_attributed_retention(output, source="Rust")
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
