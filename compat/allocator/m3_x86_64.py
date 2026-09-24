#!/usr/bin/env python3
"""Run the fail-closed native x86-64 allocator M3 local-engine gate.

M3 (``plan.md`` Milestones) requires Heap/Theap bootstrap, page queues, local
allocation/free, retirement/reuse, the complete selected bin/page-class
matrix, deterministic differential traces, and Miri-compatible execution.
``m3-local-engine-x86_64-v3.5.0.json`` names each component, the evidence that
proves it, and every condition still unmet. This runner executes that
evidence and reports the milestone ``complete`` only when every prerequisite,
check, and component passes; otherwise it names the unmet conditions and
exits 3.

The differential generates deterministic workloads (logical allocation IDs,
seeded operation mixes, and a complete reachable-bin sweep), runs each one
through the pinned mimalloc v3.5.0 C default Theap and the Rust local engine
in separate processes, and compares their normalized traces line by line.
Both producers use the source non-abandoning local profile
(``mi_option_page_full_retain == -1``) over one committed, pinned, zero
in-place arena of the same size. The trace format is owned jointly by
``m3_local_trace_x86_64.c`` and ``crabc-mimalloc/src/single_thread/local_trace.rs``.

This is private native Linux/x86-64 allocator-engine evidence. It does not
claim remote-free, abandonment, reclaim, thread-exit, aligned/zeroed/realloc,
public ``mi_*``, libc integration, backend promotion, or AArch64 behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
CONTRACT_PATH = ROOT / "compat/allocator/m3-local-engine-x86_64-v3.5.0.json"
C_DRIVER_PATH = ROOT / "compat/allocator/m3_local_trace_x86_64.c"
RUST_DRIVER_PATH = ROOT / "crabc-mimalloc/src/single_thread/local_trace.rs"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
RUST_TRACE_TEST = "single_thread::local_trace::emit_m3_local_trace"
WORKLOAD_ENV = "CRABC_M3_LOCAL_TRACE_WORKLOAD"
OUTPUT_ENV = "CRABC_M3_LOCAL_TRACE_OUTPUT"
WORKLOAD_MAGIC = "m3-local-trace 1"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-local-engine-latest.json"
DIFFERENTIAL_REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-local-trace-latest.json"
MIRI_REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-miri-latest.json"
ARTIFACT_ROOT = run.ARTIFACT_ROOT / "x86_64/m3-local-engine"


class GateError(RuntimeError):
    """The M3 runner could not execute or interpret its evidence."""


# ---------------------------------------------------------------------------
# Pinned x86-64 release geometry used by the workload generator. The traces
# themselves record the engine's actual block sizes; these values only size
# workloads so that every bin fills more than one page.
# ---------------------------------------------------------------------------

WORD = 8
KIB = 1024
MIB = KIB * KIB
SMALL_SIZE_MAX = 128 * WORD
SMALL_PAGE_SIZE = 64 * KIB
MEDIUM_PAGE_SIZE = 8 * SMALL_PAGE_SIZE
LARGE_PAGE_SIZE = WORD * MEDIUM_PAGE_SIZE
SMALL_MAX_OBJ_SIZE = (SMALL_PAGE_SIZE - 4 * KIB) // 6
MEDIUM_MAX_OBJ_SIZE = (MEDIUM_PAGE_SIZE - 4 * KIB) // 6
LARGE_MAX_OBJ_SIZE = LARGE_PAGE_SIZE // 8
LARGE_MAX_OBJ_WSIZE = LARGE_MAX_OBJ_SIZE // WORD
BIN_HUGE = 73
BIN_FULL = 74
ARENA_MIN_SIZE = 32 * MIB


def source_bin(size: int) -> int:
    """Port of pinned `page-queue.c:mi_bin` for the x86-64 `MI_ALIGN2W` profile."""

    wsize = (size + WORD - 1) // WORD
    if wsize <= 8:
        return 1 if wsize <= 1 else (wsize + 1) & ~1
    if wsize > LARGE_MAX_OBJ_WSIZE:
        return BIN_HUGE
    wsize -= 1
    highest = wsize.bit_length() - 1
    return ((highest << 2) + ((wsize >> (highest - 2)) & 0x03)) - 3


def reachable_bin_ranges() -> dict[int, tuple[int, int]]:
    """Returns every reachable regular bin with its inclusive request range."""

    ranges: dict[int, list[int]] = {}
    for wsize in range(1, LARGE_MAX_OBJ_WSIZE + 1):
        low = (wsize - 1) * WORD + 1
        high = wsize * WORD
        bin_index = source_bin(high)
        assert source_bin(low) == bin_index
        entry = ranges.setdefault(bin_index, [low, high])
        entry[1] = high
    return {bin_index: (low, high) for bin_index, (low, high) in sorted(ranges.items())}


def page_size_for_block(block_size: int) -> int:
    if block_size <= SMALL_MAX_OBJ_SIZE:
        return SMALL_PAGE_SIZE
    if block_size <= MEDIUM_MAX_OBJ_SIZE:
        return MEDIUM_PAGE_SIZE
    return LARGE_PAGE_SIZE


def page_class(block_size: int) -> str:
    if block_size <= SMALL_SIZE_MAX:
        return "direct-small"
    if block_size <= SMALL_MAX_OBJ_SIZE:
        return "small"
    if block_size <= MEDIUM_MAX_OBJ_SIZE:
        return "medium"
    if block_size <= LARGE_MAX_OBJ_SIZE:
        return "large"
    return "singleton"


class SplitMix64:
    """Deterministic, explicitly non-cryptographic workload sequence."""

    MASK = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        self.state = seed & self.MASK

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & self.MASK
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & self.MASK
        return value ^ (value >> 31)

    def below(self, bound: int) -> int:
        assert bound > 0
        return self.next() % bound


class WorkloadBuilder:
    """Accumulates one workload with never-reused logical allocation IDs."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.next_id = 0
        self.live: dict[int, int] = {}

    def allocate(self, size: int) -> int:
        assert size > 0
        identifier = self.next_id
        self.next_id += 1
        self.live[identifier] = size
        self.lines.append(f"a {identifier} {size}")
        return identifier

    def free(self, identifier: int) -> None:
        del self.live[identifier]
        self.lines.append(f"f {identifier}")

    def free_all(self, identifiers: Iterable[int]) -> None:
        for identifier in list(identifiers):
            self.free(identifier)

    def render(self, arena_bytes: int) -> str:
        assert not self.live, "every workload frees all of its allocations"
        header = [WORKLOAD_MAGIC, f"arena_bytes={arena_bytes} ids={self.next_id}"]
        return "\n".join(header + self.lines) + "\n"


def bin_matrix_workload() -> WorkloadBuilder:
    """Sweeps every reachable regular bin past one page, then the huge bin.

    Each bin allocates enough blocks to fill one page and open a second
    (moving the first to `BIN_FULL`), frees alternating blocks (unfull and
    local-free lists), reuses a few freed blocks, and frees the rest in
    reverse so its pages retire or release. The requests alternate between
    the smallest and largest byte size mapped to the bin.
    """

    builder = WorkloadBuilder()
    for bin_index, (low, high) in reachable_bin_ranges().items():
        per_page = page_size_for_block(high) // high + 1
        blocks = [builder.allocate(low if index % 2 == 0 else high) for index in range(per_page + 1)]
        for identifier in blocks[::2]:
            builder.free(identifier)
        survivors = blocks[1::2]
        survivors += [builder.allocate(high) for _ in range(min(4, len(blocks) // 2))]
        builder.free_all(reversed(survivors))
    huge = [
        builder.allocate(size)
        for size in (LARGE_MAX_OBJ_SIZE + 1, MIB, 3 * MIB + 17, 2 * MIB - 5)
    ]
    builder.free(huge[1])
    huge.append(builder.allocate(LARGE_MAX_OBJ_SIZE + WORD))
    builder.free_all([huge[0], huge[4], huge[3], huge[2]])
    return builder


RETIRE_PROBE_SIZES = (8, 48, 1000, 1024, 1025, 4096, 10240, 10241, 40000, 86016, 100_000, 524_288)


def retire_reuse_workload() -> WorkloadBuilder:
    """Targets retirement, quick reuse, candidate search, and fresh-page cycles."""

    builder = WorkloadBuilder()
    rng = SplitMix64(0x4D335F5245544952)  # "M3_RETIR"
    for size in RETIRE_PROBE_SIZES:
        per_page = page_size_for_block(size) // size + 1
        # Ping-pong on one page: retire at used == 0, then quick reuse.
        # Pinned `mi_page_malloc_zero` pops without touching
        # `retire_expire` and `free.c` does not re-retire, so the countdown
        # stays put; an engine that clears it on a pop diverges at step 3.
        for _ in range(20):
            builder.free(builder.allocate(size))
        if per_page > 1024:
            # Multi-page phases for the tiniest classes would only repeat
            # the same queue transitions thousands of times per page.
            continue
        # Five pages in one bin, all freed in allocation order: source
        # retirement keeps at most three per queue and only small blocks
        # below `MI_SMALL_SIZE_MAX` can retire alongside others.
        pages = [builder.allocate(size) for _ in range(5 * per_page)]
        builder.free_all(pages)
        # Fresh pages in a neighbour bin advance retirement expiry through
        # `_mi_theap_collect_retired` on the slow path.
        neighbour = size * 2 if size * 2 <= LARGE_MAX_OBJ_SIZE else size // 3
        neighbour_blocks = [builder.allocate(neighbour) for _ in range(3 * (page_size_for_block(neighbour) // neighbour + 1))]
        # Candidate search across differently used pages.
        pages = [builder.allocate(size) for _ in range(6 * per_page)]
        chosen: list[int] = []
        for position, identifier in enumerate(pages):
            page_number = position // per_page
            keep = {0: 1, 1: 2, 2: 8, 3: 1, 4: 3, 5: 1}.get(page_number, 1)
            if (position % keep) != 0 or page_number in (3,):
                builder.free(identifier)
            else:
                chosen.append(identifier)
        extra = [builder.allocate(size) for _ in range(per_page // 2 + 2)]
        survivors = chosen + extra
        order = list(survivors)
        for index in range(len(order) - 1, 0, -1):
            swap = rng.below(index + 1)
            order[index], order[swap] = order[swap], order[index]
        builder.free_all(order)
        builder.free_all(neighbour_blocks)
    return builder


def generic_administration_workload(calls: int) -> WorkloadBuilder:
    """Drives `_mi_malloc_generic` past its mini and full administration.

    Every request above `MI_SMALL_SIZE_MAX` enters the generic path, so
    `calls` of them cross the 1,000-call mini-collection threshold and the
    frozen 10,000-call `mi_option_generic_collect` full collection. A small
    rotating live set keeps pages retiring and being reused throughout.
    """

    builder = WorkloadBuilder()
    sizes = (1032, 2048, 12_000, 100_000)
    window: list[int] = []
    for call in range(calls):
        window.append(builder.allocate(sizes[call % len(sizes)]))
        if len(window) > 6:
            builder.free(window.pop(0))
    builder.free_all(window)
    return builder


def random_mix_workload(seed: int, steps: int, live_cap_bytes: int) -> WorkloadBuilder:
    """A seeded owner-local churn across every page class."""

    rng = SplitMix64(seed)
    ranges = reachable_bin_ranges()
    classes: dict[str, list[int]] = {}
    for bin_index, (_, high) in ranges.items():
        classes.setdefault(page_class(high), []).append(bin_index)
    weights = (("direct-small", 48), ("small", 24), ("medium", 16), ("large", 9), ("singleton", 3))
    total_weight = sum(weight for _, weight in weights)
    builder = WorkloadBuilder()
    live: list[int] = []
    live_bytes = 0
    for _ in range(steps):
        allocate = not live or (rng.below(100) < 55 and len(live) < 6000)
        if allocate:
            pick = rng.below(total_weight)
            for name, weight in weights:
                if pick < weight:
                    break
                pick -= weight
            if name == "singleton":
                size = LARGE_MAX_OBJ_SIZE + 1 + rng.below(3 * MIB)
            else:
                bins = classes[name]
                low, high = ranges[bins[rng.below(len(bins))]]
                size = low + rng.below(high - low + 1)
            if live_bytes + size > live_cap_bytes:
                allocate = False
        if allocate:
            live.append(builder.allocate(size))
            live_bytes += size
        else:
            index = rng.below(len(live))
            identifier = live[index]
            live[index] = live[-1]
            live.pop()
            live_bytes -= builder.live[identifier]
            builder.free(identifier)
    while live:
        index = rng.below(len(live))
        identifier = live[index]
        live[index] = live[-1]
        live.pop()
        builder.free(identifier)
    return builder


def generate_workloads(contract: Mapping[str, Any]) -> dict[str, str]:
    arena_bytes = int(contract["profile"]["arena_bytes"])
    generators = {
        "bin-matrix": lambda parameters: bin_matrix_workload(),
        "retire-reuse": lambda parameters: retire_reuse_workload(),
        "generic-administration": lambda parameters: generic_administration_workload(
            int(parameters["calls"])
        ),
        "random-mix": lambda parameters: random_mix_workload(
            int(parameters["seed"], 0), int(parameters["steps"]), int(parameters["live_cap_bytes"])
        ),
    }
    rendered: dict[str, str] = {}
    for workload in contract["workloads"]:
        builder = generators[workload["generator"]](workload.get("parameters", {}))
        rendered[workload["id"]] = builder.render(arena_bytes)
    return rendered


# ---------------------------------------------------------------------------
# Trace production and comparison.
# ---------------------------------------------------------------------------


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def c_driver_command(compiler: str, source: Path, binary: Path, contract: Mapping[str, Any]) -> list[str]:
    build = contract["c_oracle"]
    return [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *build["compile_definitions"],
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *run.CONFIGURATION_PROFILES["release"],
        str(C_DRIVER_PATH),
        *(str(source / member) for member in build["release_source_set"]),
        "-pthread",
        "-o",
        str(binary),
    ]


def build_c_driver(contract: Mapping[str, Any], work: Path, offline: bool) -> dict[str, Any]:
    pin = run.load_pin()
    archive = run.fetch_archive(pin, offline)
    source = run.safe_extract(archive, work / "source", pin["archive_root"])
    compiler = run.require_tool("musl-gcc")
    binary = work / "m3-local-trace-c"
    command = c_driver_command(compiler, source, binary, contract)
    record = run.command_record(command, cwd=source, timeout_seconds=600)
    run.require_success(record, "pinned C M3 local-trace driver build")
    return {
        "archive_sha256": run.sha256_file(archive),
        "binary": binary,
        "driver_sha256": run.sha256_file(C_DRIVER_PATH),
        "source": source,
    }


def c_environment(contract: Mapping[str, Any]) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("MIMALLOC_")
    }
    environment.update(contract["c_oracle"]["environment"])
    return environment


def run_c_trace(binary: Path, workload: Path, output: Path, contract: Mapping[str, Any]) -> None:
    record = run.command_record(
        (str(binary), str(workload), str(output)),
        cwd=workload.parent,
        env=c_environment(contract),
        timeout_seconds=1800,
    )
    run.require_success(record, f"pinned C M3 local trace for {workload.name}")


def rust_test_binary() -> Path:
    command = [
        "cargo", "test", "--locked", "--target", TARGET, "-p", "crabc-mimalloc", "--lib",
        "--no-default-features", "--no-run", "--message-format=json",
    ]
    record = run.command_record(command, cwd=ROOT, timeout_seconds=3600)
    run.require_success(record, "Rust M3 local-trace test build")
    executables: list[str] = []
    for line in str(record["stdout"]).splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "crabc_mimalloc"
            and message.get("profile", {}).get("test")
            and message.get("executable")
        ):
            executables.append(message["executable"])
    if len(executables) != 1:
        raise GateError(f"expected one crabc-mimalloc unit test executable, found {executables}")
    return Path(executables[0])


def run_rust_trace(binary: Path, workload: Path, output: Path) -> None:
    environment = {
        name: value for name, value in os.environ.items() if not name.lower().startswith("mimalloc_")
    }
    environment[WORKLOAD_ENV] = str(workload)
    environment[OUTPUT_ENV] = str(output)
    record = run.command_record(
        (str(binary), RUST_TRACE_TEST, "--exact", "--nocapture", "--test-threads=1"),
        cwd=ROOT,
        env=environment,
        timeout_seconds=3600,
    )
    run.require_success(record, f"Rust M3 local trace for {workload.name}")
    if run.parse_rust_test_count(str(record["stdout"]) + "\n" + str(record["stderr"])) != 1:
        raise GateError(f"Rust M3 local trace for {workload.name} did not run exactly one test")


def first_divergence(c_lines: Sequence[str], rust_lines: Sequence[str]) -> dict[str, Any] | None:
    for index, (c_line, rust_line) in enumerate(zip(c_lines, rust_lines)):
        if c_line != rust_line:
            break
    else:
        if len(c_lines) == len(rust_lines):
            return None
        index = min(len(c_lines), len(rust_lines))
    step = next(
        (line for line in reversed(c_lines[: index + 1]) if line.startswith("@")),
        "bootstrap",
    )
    return {
        "line": index + 1,
        "operation": step,
        "c": c_lines[max(0, index - 6): index + 6],
        "rust": rust_lines[max(0, index - 6): index + 6],
    }


PAGE_LINE = re.compile(
    r"^([+~])P(\d+) q(\d+) s(\d+) c(\d+) r(\d+) u(\d+) f(\S+) l(\S+) x(\d+) F([01]) z([01]) S(\d+)$"
)


def trace_coverage(lines: Iterable[str]) -> dict[str, Any]:
    """Derives the observed bin/page-class transition matrix from one trace."""

    block_bin: dict[int, int] = {}
    pages: dict[int, dict[str, int]] = {}
    events: dict[int, set[str]] = {}
    direct_indices: set[int] = set()
    operations = allocations = frees = 0
    admin_mini = admin_full = 0
    previous_global: dict[str, int] = {}
    for line in lines:
        if line.startswith("B"):
            bin_text, size_text = line[1:].split()
            # Bin 0 is the unused source placeholder sharing bin 1's size.
            if 0 < int(bin_text) < BIN_HUGE:
                block_bin.setdefault(int(size_text), int(bin_text))
            continue
        if line.startswith("@"):
            operations += 1
            allocations += " a" in line
            frees += " f" in line
            continue
        if line.startswith("D") and not line.endswith(" -"):
            direct_indices.add(int(line[1:].split()[0]))
            continue
        if line.startswith("G "):
            fields = {match[0]: int(match[1]) for match in re.findall(r"([a-z]+)(-?\d+)", line[2:])}
            if previous_global and fields["gcc"] > previous_global["gcc"]:
                admin_mini += 1
            if previous_global and fields["gcc"] == 0 and previous_global["gcc"] > 0:
                admin_full += 1
            previous_global = fields
            continue
        if line.startswith("-P"):
            pid = int(line[2:])
            page = pages.pop(pid)
            events.setdefault(page["bin"], set()).add("released")
            continue
        match = PAGE_LINE.match(line)
        if match is None:
            continue
        kind, pid, queue, size, _, _, used, _, _, expire, in_full, _, _ = match.groups()
        pid, queue, size, used, expire = int(pid), int(queue), int(size), int(used), int(expire)
        home = BIN_HUGE if size > LARGE_MAX_OBJ_SIZE else block_bin.get(size, source_bin(size))
        observed = events.setdefault(home, set())
        previous = pages.get(pid)
        if kind == "+":
            observed.add("created")
        if queue == BIN_FULL:
            observed.add("full")
        if previous is not None:
            if previous["queue"] == BIN_FULL and queue != BIN_FULL:
                observed.add("unfull")
            if previous["expire"] > 0 and expire == 0 and used > previous["used"]:
                observed.add("retired-reuse")
        if expire > 0:
            observed.add("retired")
        pages[pid] = {"bin": home, "queue": queue, "used": used, "expire": expire}
    return {
        "admin_full_collections": admin_full,
        "admin_mini_collections": admin_mini,
        "allocations": allocations,
        "bins": {str(bin_index): sorted(names) for bin_index, names in sorted(events.items())},
        "direct_indices": sorted(direct_indices),
        "frees": frees,
        "operations": operations,
    }


def merge_coverage(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    merged_bins: dict[str, set[str]] = {}
    direct: set[int] = set()
    totals = {"admin_full_collections": 0, "admin_mini_collections": 0, "allocations": 0, "frees": 0, "operations": 0}
    for record in records:
        for bin_index, names in record["bins"].items():
            merged_bins.setdefault(bin_index, set()).update(names)
        direct.update(record["direct_indices"])
        for key in totals:
            totals[key] += record[key]
    return {
        **totals,
        "bins": {key: sorted(value) for key, value in sorted(merged_bins.items(), key=lambda item: int(item[0]))},
        "direct_indices": sorted(direct),
    }


def coverage_unmet(coverage: Mapping[str, Any], requirements: Mapping[str, Any]) -> list[str]:
    unmet: list[str] = []
    bins = coverage["bins"]
    for bin_index in reachable_bin_ranges():
        missing = sorted(set(requirements["regular_bin_events"]) - set(bins.get(str(bin_index), [])))
        if missing:
            unmet.append(f"bin {bin_index} lacks {', '.join(missing)}")
    missing_huge = sorted(set(requirements["huge_bin_events"]) - set(bins.get(str(BIN_HUGE), [])))
    if missing_huge:
        unmet.append(f"huge bin lacks {', '.join(missing_huge)}")
    for name in requirements["retired_reuse_classes"]:
        if not any(
            "retired-reuse" in bins.get(str(bin_index), [])
            for bin_index, (_, high) in reachable_bin_ranges().items()
            if page_class(high) == name
        ):
            unmet.append(f"no {name} page was reused after retirement")
    direct_expected = set(range(1, SMALL_SIZE_MAX // WORD + 1))
    missing_direct = sorted(direct_expected - set(coverage["direct_indices"]))
    if missing_direct:
        unmet.append(f"direct-page cache indices never populated: {missing_direct[:8]}")
    if coverage["admin_mini_collections"] < requirements["minimum_admin_mini_collections"]:
        unmet.append("generic administration mini-collections were not exercised")
    if coverage["admin_full_collections"] < requirements["minimum_admin_full_collections"]:
        unmet.append("generic administration full collections were not exercised")
    return unmet


def run_differential(contract: Mapping[str, Any], *, offline: bool) -> dict[str, Any]:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    workloads = generate_workloads(contract)
    results: list[dict[str, Any]] = []
    with run.temporary_directory(prefix="crabc-mimalloc-m3-local-trace-") as temporary_name:
        work = Path(temporary_name)
        c_build = build_c_driver(contract, work, offline)
        rust_binary = rust_test_binary()
        for name, text in workloads.items():
            workload = ARTIFACT_ROOT / f"{name}.workload"
            workload.write_text(text, encoding="utf-8")
            c_output = ARTIFACT_ROOT / f"{name}.c.trace"
            c_repeat = work / f"{name}.c.repeat.trace"
            rust_output = ARTIFACT_ROOT / f"{name}.rust.trace"
            run_c_trace(c_build["binary"], workload, c_output, contract)
            run_c_trace(c_build["binary"], workload, c_repeat, contract)
            run_rust_trace(rust_binary, workload, rust_output)
            c_lines = c_output.read_text(encoding="utf-8").splitlines()
            rust_lines = rust_output.read_text(encoding="utf-8").splitlines()
            repeat_matches = c_repeat.read_bytes() == c_output.read_bytes()
            divergence = first_divergence(c_lines, rust_lines)
            digest = sha256_bytes(text.encode("utf-8"))
            results.append(
                {
                    "c_repeat_identical": repeat_matches,
                    "c_trace_sha256": run.sha256_file(c_output),
                    "coverage": trace_coverage(c_lines),
                    "divergence": divergence,
                    "id": name,
                    "rust_trace_sha256": run.sha256_file(rust_output),
                    "status": "matched" if divergence is None and repeat_matches else "diverged",
                    "trace_lines": len(c_lines),
                    "workload_sha256": digest,
                }
            )
        report = {
            "archive_sha256": c_build["archive_sha256"],
            "c_driver_sha256": c_build["driver_sha256"],
            "coverage": merge_coverage(result["coverage"] for result in results),
            "rust_driver_sha256": run.sha256_file(RUST_DRIVER_PATH),
            "workloads": results,
        }
    report["coverage_unmet"] = coverage_unmet(report["coverage"], contract["coverage_requirements"])
    unmet: list[str] = []
    for result in results:
        if result["status"] != "matched":
            where = result["divergence"]["operation"] if result["divergence"] else "C repeat"
            unmet.append(f"workload {result['id']} diverged at {where}")
    unmet += [f"coverage: {item}" for item in report["coverage_unmet"]]
    report["unmet"] = unmet
    report["status"] = "passed" if not unmet else "failed"
    return report


# ---------------------------------------------------------------------------
# Rust unit batch and Miri execution.
# ---------------------------------------------------------------------------

TEST_RESULT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)$", re.MULTILINE)
TEST_LISTING = re.compile(r"^(\S+): test$", re.MULTILINE)


def select_by_prefix(listing: str, prefixes: Sequence[str]) -> dict[str, list[str]]:
    """Groups listed test names under each module prefix.

    libtest filters match substrings (``page::tests::`` also selects
    ``main_heap_page::tests::``), so selection uses the ``--list`` output and
    true path prefixes, then runs each group with ``--exact``.
    """

    names = TEST_LISTING.findall(listing)
    return {prefix: sorted(name for name in names if name.startswith(prefix)) for prefix in prefixes}


def summarize_group(prefix: str, selected: Sequence[str], record: Mapping[str, Any]) -> dict[str, Any]:
    output = str(record["stdout"]) + "\n" + str(record["stderr"])
    outcomes = dict(TEST_RESULT.findall(output))
    passed = sorted(name for name in selected if outcomes.get(name) == "ok")
    failed = sorted(name for name in selected if outcomes.get(name) == "FAILED")
    # A test that never reported (for example after Miri aborted the process
    # on undefined behaviour) is unmet, never silently skipped.
    unreported = sorted(name for name in selected if name not in outcomes)
    unmet = [f"test failed: {name}" for name in failed]
    unmet += [f"test did not complete: {name}" for name in unreported]
    if record["status"] != 0 and not unmet:
        unmet.append(f"{prefix} group exited {record['status']}")
    if not selected:
        unmet.append(f"no tests are selected under {prefix}")
    elif not passed:
        unmet.append(f"no passing tests under {prefix}")
    return {
        "exit_status": record["status"],
        "failed": failed,
        "passed": len(passed),
        "selected": len(selected),
        "unmet": unmet,
        "unreported": unreported,
    }


def run_unit_batch(contract: Mapping[str, Any], binary: Path) -> dict[str, Any]:
    prefixes = contract["rust_unit_batch"]["module_prefixes"]
    listing = run.command_record((str(binary), "--list", "--format", "terse"), cwd=ROOT, timeout_seconds=600)
    run.require_success(listing, "Rust M3 unit test listing")
    groups = select_by_prefix(str(listing["stdout"]), prefixes)
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    logs: list[str] = []
    results: dict[str, Any] = {}
    unmet: list[str] = []
    for prefix, selected in groups.items():
        record = run.command_record(
            (str(binary), "--exact", "--test-threads=1", *selected),
            cwd=ROOT,
            timeout_seconds=7200,
        ) if selected else {"status": 0, "stdout": "", "stderr": ""}
        logs.append(f"### {prefix}\n{record['stdout']}\n{record['stderr']}")
        results[prefix] = summarize_group(prefix, selected, record)
        unmet += [f"{prefix} {item}" for item in results[prefix]["unmet"]]
    (ARTIFACT_ROOT / "rust-unit-batch.log").write_text("\n".join(logs), encoding="utf-8")
    return {
        "binary": str(binary),
        "groups": results,
        "passed": sum(group["passed"] for group in results.values()),
        "status": "passed" if not unmet else "failed",
        "unmet": unmet,
    }


def run_miri(contract: Mapping[str, Any]) -> dict[str, Any]:
    miri = contract["miri"]
    probe = run.command_record(("cargo", "miri", "--version"), cwd=ROOT, timeout_seconds=600)
    if probe["status"] != 0:
        # The pinned image installs the component; an older image must be
        # rebuilt rather than mutated inside a disposable container.
        return {
            "status": "unavailable",
            "unmet": [
                "Miri is not installed for the pinned toolchain in the allocator image "
                f"(`cargo miri --version` exited {probe['status']}); rebuild it with "
                "`./compat/allocator/run-x86_64.sh image`"
            ],
        }
    base = [
        "cargo", "miri", "test", "--locked", "--target", miri["target"], "-p", "crabc-mimalloc",
        "--lib", "--no-default-features", "--",
    ]
    environment = dict(os.environ)
    environment["MIRIFLAGS"] = " ".join(miri["miriflags"])
    # Miri's sysroot builder creates a temporary Cargo package. Under the
    # launcher's `/workspace/.work/...` TMPDIR, Cargo would adopt it into the
    # checkout workspace and refuse it. The launcher bind-mounts the container
    # `/tmp` onto the same checkout-local work directory, so this path keeps
    # both the temporary package and the cached sysroot inside that boundary.
    environment["TMPDIR"] = "/tmp"
    environment["XDG_CACHE_HOME"] = "/tmp/crabc-m3-miri-cache"
    listing = run.command_record(
        (*base, "--list", "--format", "terse"), cwd=ROOT, env=environment, timeout_seconds=7200
    )
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    if listing["status"] != 0:
        (ARTIFACT_ROOT / "miri.log").write_text(
            str(listing["stdout"]) + "\n" + str(listing["stderr"]), encoding="utf-8"
        )
        return {
            "status": "failed",
            "unmet": [f"cargo miri test --list exited {listing['status']}"],
            "version": str(probe["stdout"]).strip(),
        }
    groups = select_by_prefix(str(listing["stdout"]), miri["module_prefixes"])
    logs: list[str] = []
    results: dict[str, Any] = {}
    unmet: list[str] = []
    passed: set[str] = set()
    # Miri stops a whole process at the first undefined behaviour, so each
    # module group runs in its own process and reports independently.
    for prefix, selected in groups.items():
        record = run.command_record(
            (*base, "--exact", "--test-threads=1", *selected),
            cwd=ROOT,
            env=environment,
            timeout_seconds=7200,
        ) if selected else {"status": 0, "stdout": "", "stderr": ""}
        logs.append(f"### {prefix}\n{record['stdout']}\n{record['stderr']}")
        results[prefix] = summarize_group(prefix, selected, record)
        unmet += [f"{prefix} {item}" for item in results[prefix]["unmet"]]
        output = str(record["stdout"]) + "\n" + str(record["stderr"])
        passed.update(name for name, outcome in TEST_RESULT.findall(output) if outcome == "ok")
    (ARTIFACT_ROOT / "miri.log").write_text("\n".join(logs), encoding="utf-8")
    for name in miri["required_tests"]:
        if name not in passed:
            unmet.append(f"required Miri test did not pass: {name}")
    return {
        "groups": results,
        "miriflags": list(miri["miriflags"]),
        "passed": len(passed),
        "status": "passed" if not unmet else "failed",
        "unmet": unmet,
        "version": str(probe["stdout"]).strip(),
    }


# ---------------------------------------------------------------------------
# Gate.
# ---------------------------------------------------------------------------


def prerequisite_status(contract: Mapping[str, Any]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    unmet: list[str] = []
    for prerequisite in contract["milestone"]["prerequisites"]:
        path = run.WORK_ROOT / prerequisite["report"]
        status = "absent"
        if path.is_file():
            try:
                status = str(json.loads(path.read_text(encoding="utf-8"))["milestone"]["status"])
            except (OSError, KeyError, TypeError, json.JSONDecodeError):
                status = "unreadable"
        results[prerequisite["milestone"]] = {"report": prerequisite["report"], "status": status}
        if status != "complete":
            unmet.append(f"prerequisite {prerequisite['milestone'].upper()} is {status}, not complete")
    return {"milestones": results, "unmet": unmet}


def evaluate_gate(contract: Mapping[str, Any], checks: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for component in contract["components"]:
        unmet: list[str] = []
        for check in component["checks"]:
            result = checks.get(check)
            if result is None:
                unmet.append(f"check {check} did not run")
            elif result.get("status") != "passed":
                unmet.extend(f"{check}: {item}" for item in result.get("unmet", [f"status {result.get('status')}"]))
        unmet.extend(component["remaining_conditions"])
        components.append(
            {"id": component["id"], "status": "complete" if not unmet else "incomplete", "unmet": unmet}
        )
    prerequisites = checks["prerequisites"]
    incomplete = [component for component in components if component["status"] != "complete"]
    status = "complete" if not incomplete and not prerequisites["unmet"] else "incomplete"
    return {
        "components": components,
        "prerequisites": prerequisites,
        "status": status,
    }


def unmet_message(gate: Mapping[str, Any]) -> str:
    lines = ["allocator M3 local engine is incomplete:"]
    lines += [f"  - {item}" for item in gate["prerequisites"]["unmet"]]
    for component in gate["components"]:
        for item in component["unmet"]:
            lines.append(f"  - [{component['id']}] {item}")
    return "\n".join(lines)


def load_contract() -> dict[str, Any]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if contract.get("schema") != "crabc-mimalloc-x86_64-m3-local-engine" or contract.get("format") != 1:
        raise GateError("M3 contract schema drifted")
    pin = run.load_pin()
    upstream = contract["upstream"]
    if upstream["revision"] != pin["revision"] or upstream["archive_sha256"] != pin["sha256"]:
        raise GateError("M3 contract upstream pin drifted")
    return contract


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="require the verified source archive to be cached")
    parser.add_argument(
        "--differential-only",
        action="store_true",
        help="run only the C/Rust trace differential and coverage (development; no gate report)",
    )
    parser.add_argument(
        "--miri-only",
        action="store_true",
        help="run only the Miri component (development; no gate report)",
    )
    options = parser.parse_args(arguments)
    try:
        contract = load_contract()
        provenance = run.require_native_x86_64()
        lockfile = run.sha256_file(LOCKFILE)
        if options.miri_only:
            miri = run_miri(contract)
            run.write_json(MIRI_REPORT_PATH, {"miri": miri, "provenance": provenance})
            print(MIRI_REPORT_PATH)
            if miri["status"] != "passed":
                print("\n".join(["M3 Miri component failed:", *(f"  - {item}" for item in miri["unmet"])]), file=sys.stderr)
                return 1
            return 0
        differential = run_differential(contract, offline=options.offline)
        if options.differential_only:
            report = {"differential": differential, "provenance": provenance}
            run.write_json(DIFFERENTIAL_REPORT_PATH, report)
            print(DIFFERENTIAL_REPORT_PATH)
            if differential["status"] != "passed":
                print("\n".join(["M3 local trace differential failed:", *(f"  - {item}" for item in differential["unmet"])]), file=sys.stderr)
                return 1
            return 0
        checks: dict[str, Any] = {
            "prerequisites": prerequisite_status(contract),
            "local-trace-differential": differential,
            "rust-unit-batch": run_unit_batch(contract, rust_test_binary()),
            "miri": run_miri(contract),
        }
        if run.sha256_file(LOCKFILE) != lockfile:
            raise GateError("Cargo.lock changed during the --locked M3 gate")
        gate = evaluate_gate(contract, checks)
        report = {
            "checks": checks,
            "contract_sha256": run.sha256_file(CONTRACT_PATH),
            "format": 1,
            "kind": "mimalloc-x86_64-m3-local-engine-gate",
            "milestone": {"id": "m3", "status": gate["status"]},
            "gate": gate,
            "provenance": provenance,
            "upstream": contract["upstream"],
        }
        run.write_json(REPORT_PATH, report)
        print(REPORT_PATH)
        if gate["status"] != "complete":
            print(f"UNMET MILESTONE: {unmet_message(gate)}", file=sys.stderr)
            return 3
        return 0
    except (GateError, run.HarnessError, OSError, KeyError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
