#!/usr/bin/env python3
"""Run the fail-closed native x86-64 allocator local-engine gate.

The local engine requires Heap/Theap bootstrap, page queues, local
allocation/free, retirement/reuse, the selected bin/page-class matrix,
deterministic differential traces, and Miri-compatible execution. The gate
executes each selected check and completes only after its prerequisites and
every component pass; otherwise it names the unmet conditions and exits 3.
The qualification receipt binds the checks to one clean Git revision and one
immutable native image before and after execution. Prerequisite receipts must
attest that same source and image. Dirty or changed source, or changed native
execution provenance, cannot publish the qualification receipt.

The differential generates deterministic workloads (logical allocation IDs,
seeded operation mixes, and a complete reachable-bin sweep), runs each one
through the pinned mimalloc v3.5.0 C default Theap and the Rust local engine
in separate processes, and compares their normalized traces line by line.
Both producers use the source non-abandoning local profile
(``mi_option_page_full_retain == -1``) over one committed, pinned, zero
in-place arena of the same size. Both trace producers use one normalized
line format.

The persistent-owner differential drives the production default Theap
through ``native_allocate_aligned(size, 16)``/``native_free`` on the initial
owner and on one later owner, each in a fresh process, and
compares it with the same C driver's ``initial``/``later`` modes over
``mi_malloc_aligned(size, 16)``/``mi_free``. Its workloads never fill a page,
so the default abandoning Theap stays owner-local.

The queue reorder differential builds the pinned C intrusive queue helpers
and compares their six owner-local transitions with the Rust metadata queue.
Its receipt retains both raw process outputs and the source-built C command.

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
OWNER_RUST_DRIVER_PATH = ROOT / "crabc-mimalloc/tests/native_persistent_owner_local_trace.rs"
OWNER_TRACE_AUDIT_PATH = ROOT / "crabc-mimalloc/src/theap_trace_audit.rs"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
RUST_TRACE_TEST = "single_thread::local_trace::emit_m3_local_trace"
WORKLOAD_ENV = "CRABC_M3_LOCAL_TRACE_WORKLOAD"
OUTPUT_ENV = "CRABC_M3_LOCAL_TRACE_OUTPUT"
OWNER_ENV = "CRABC_M3_OWNER_TRACE_OWNER"
OWNER_WORKLOAD_ENV = "CRABC_M3_OWNER_TRACE_WORKLOAD"
OWNER_OUTPUT_ENV = "CRABC_M3_OWNER_TRACE_OUTPUT"
FRESH_TEST_CHILD_ENV = "CRABC_MIMALLOC_FRESH_TEST_CHILD"
WORKLOAD_MAGIC = "m3-local-trace 1"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-local-engine-latest.json"
DIFFERENTIAL_REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-local-trace-latest.json"
OWNER_REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-persistent-owner-trace-latest.json"
MIRI_REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-miri-latest.json"
QUEUE_REORDER_REPORT_PATH = run.REPORT_ROOT / "x86_64/m3-queue-reorder-latest.json"
ARTIFACT_ROOT = run.ARTIFACT_ROOT / "x86_64/m3-local-engine"


class GateError(RuntimeError):
    """The local-engine runner could not execute or interpret its evidence."""


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


def queue_candidate_front_workload(size: int, freed_from_first: int) -> WorkloadBuilder:
    """Select an older queue member behind an expandable, unavailable head.

    A full first page moves to BIN_FULL when a second page opens. Local frees
    append the first page behind that new head. The head has no immediate free
    block yet can extend, so the source candidate search visits both members,
    prefers the older page's available blocks, and moves it to the front.
    """

    builder = WorkloadBuilder()
    per_page = page_size_for_block(size) // size
    first = [builder.allocate(size) for _ in range(per_page)]
    second = builder.allocate(size)
    for identifier in first[:freed_from_first]:
        builder.free(identifier)
    replacements = [builder.allocate(size) for _ in range(freed_from_first)]
    builder.free_all(first[freed_from_first:])
    builder.free(second)
    builder.free_all(replacements)
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


def nonfilling_bin_cap(block_size: int) -> int:
    """A per-bin live-block bound strictly below one page's reserved count.

    `page_size_for_block` less a 4 KiB page-info allowance under-estimates
    the source `reserved`, so a bin whose live blocks stay at or below this
    bound can never exhaust a page: the owner-local default Theap then never
    moves a page to `BIN_FULL` or triggers allocation-time abandonment.
    """

    return max(0, (page_size_for_block(block_size) - 4 * KIB) // block_size - 1)


def owner_bin_sweep_workload(per_bin_limit: int) -> WorkloadBuilder:
    """Visits every reachable regular bin without filling a page.

    Each bin allocates up to its non-filling bound (alternating the smallest
    and largest request mapped to it), frees alternating blocks onto the
    local free list, reuses a few, frees the rest in reverse so the page
    retires, and ping-pongs once through retired reuse. Later bins' slow
    paths advance retirement expiry, releasing earlier pages.
    """

    builder = WorkloadBuilder()
    for _, (low, high) in reachable_bin_ranges().items():
        count = min(nonfilling_bin_cap(high), per_bin_limit)
        assert count >= 1
        blocks = [builder.allocate(low if index % 2 == 0 else high) for index in range(count)]
        freed = blocks[::2]
        builder.free_all(freed)
        survivors = blocks[1::2]
        survivors += [builder.allocate(high) for _ in range(min(4, len(freed)))]
        builder.free_all(reversed(survivors))
        builder.free(builder.allocate(low))
    return builder


def owner_random_mix_workload(seed: int, steps: int, live_cap_bytes: int) -> WorkloadBuilder:
    """A seeded owner-local churn over every regular page class, holding each
    bin's live blocks within its non-filling bound. Singletons are excluded:
    a singleton page is full from its first allocation."""

    rng = SplitMix64(seed)
    ranges = reachable_bin_ranges()
    classes: dict[str, list[int]] = {}
    for bin_index, (_, high) in ranges.items():
        classes.setdefault(page_class(high), []).append(bin_index)
    weights = (("direct-small", 45), ("small", 25), ("medium", 18), ("large", 12))
    total_weight = sum(weight for _, weight in weights)
    builder = WorkloadBuilder()
    live: list[tuple[int, int]] = []
    per_bin: dict[int, int] = {}
    live_bytes = 0
    for _ in range(steps):
        allocate = not live or (rng.below(100) < 55 and len(live) < 6000)
        if allocate:
            pick = rng.below(total_weight)
            for name, weight in weights:
                if pick < weight:
                    break
                pick -= weight
            bins = classes[name]
            bin_index = bins[rng.below(len(bins))]
            low, high = ranges[bin_index]
            size = low + rng.below(high - low + 1)
            if live_bytes + size > live_cap_bytes or per_bin.get(bin_index, 0) >= nonfilling_bin_cap(high):
                allocate = False
        if allocate:
            live.append((builder.allocate(size), bin_index))
            per_bin[bin_index] = per_bin.get(bin_index, 0) + 1
            live_bytes += size
        else:
            index = rng.below(len(live))
            identifier, bin_index = live[index]
            live[index] = live[-1]
            live.pop()
            per_bin[bin_index] -= 1
            live_bytes -= builder.live[identifier]
            builder.free(identifier)
    while live:
        index = rng.below(len(live))
        identifier, _ = live[index]
        live[index] = live[-1]
        live.pop()
        builder.free(identifier)
    return builder


def generate_owner_workloads(contract: Mapping[str, Any]) -> dict[str, str]:
    generators = {
        "owner-bin-sweep": lambda parameters: owner_bin_sweep_workload(int(parameters["per_bin_limit"])),
        "owner-random-mix": lambda parameters: owner_random_mix_workload(
            int(parameters["seed"], 0), int(parameters["steps"]), int(parameters["live_cap_bytes"])
        ),
    }
    rendered: dict[str, str] = {}
    for workload in contract["persistent_owner_profile"]["workloads"]:
        builder = generators[workload["generator"]](workload.get("parameters", {}))
        # The owner profile uses the runtime's own default arena.
        rendered[workload["id"]] = builder.render(0)
    return rendered


def generate_workloads(contract: Mapping[str, Any]) -> dict[str, str]:
    arena_bytes = int(contract["profile"]["arena_bytes"])
    generators = {
        "bin-matrix": lambda parameters: bin_matrix_workload(),
        "queue-candidate-front": lambda parameters: queue_candidate_front_workload(
            int(parameters["size"]), int(parameters["freed_from_first"])
        ),
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


def c_environment(options: Mapping[str, str]) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("MIMALLOC_")
    }
    environment.update(options)
    return environment


def run_c_trace(
    binary: Path,
    workload: Path,
    output: Path,
    options: Mapping[str, str],
    mode: str = "local",
) -> None:
    record = run.command_record(
        (str(binary), str(workload), str(output), mode),
        cwd=workload.parent,
        env=c_environment(options),
        timeout_seconds=1800,
    )
    run.require_success(record, f"pinned C M3 {mode} trace for {workload.name}")


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


def queue_candidate_front_witness(
    lines: Sequence[str], size: int, freed_from_first: int
) -> dict[str, Any]:
    """Require the source's full-to-tail and candidate-to-head transitions."""

    per_page = page_size_for_block(size) // size
    second_step = per_page + 1
    before_move_step = second_step + freed_from_first
    move_step = before_move_step + 1
    regular_bin = source_bin(size)
    queues: dict[int, tuple[int, ...]] = {}
    snapshots: dict[int, dict[int, tuple[int, ...]]] = {}
    page_states: dict[int, tuple[int, int, int, str, str]] = {}
    states_by_step: dict[int, dict[int, tuple[int, int, int, str, str]]] = {}
    allocated_on_step: dict[int, int] = {}
    step = 0
    for line in lines:
        if line.startswith("@"):
            if step:
                snapshots[step] = dict(queues)
                states_by_step[step] = dict(page_states)
            step = int(line.split(" ", 1)[0][1:])
        elif line.startswith("Q"):
            parts = line.split()
            queue_bin = int(parts[0][1:])
            members = "".join(parts[1:-1])
            queues[queue_bin] = tuple(int(member) for member in members.split(",") if member)
            if len(queues[queue_bin]) != int(parts[-1][1:]):
                raise GateError(f"queue {queue_bin} trace count disagrees with its members")
        elif line.startswith("= P"):
            allocated_on_step[step] = int(line.split()[1][1:])
        elif match := PAGE_LINE.match(line):
            page_states[int(match.group(2))] = (
                int(match.group(5)), int(match.group(6)), int(match.group(7)),
                match.group(8), match.group(9),
            )
        elif line.startswith("-P"):
            page_states.pop(int(line[2:]), None)
    if step:
        snapshots[step] = dict(queues)
        states_by_step[step] = dict(page_states)

    first = allocated_on_step.get(1)
    second = allocated_on_step.get(second_step)
    regular_after_second = snapshots.get(second_step, {}).get(regular_bin)
    full_after_second = snapshots.get(second_step, {}).get(BIN_FULL)
    regular_before_move = snapshots.get(before_move_step, {}).get(regular_bin)
    regular_after_move = snapshots.get(move_step, {}).get(regular_bin)
    selected = allocated_on_step.get(move_step)
    second_before_move = states_by_step.get(before_move_step, {}).get(second)
    first_before_move = states_by_step.get(before_move_step, {}).get(first)
    unmet = []
    if first is None or second is None or first == second:
        unmet.append("two distinct source pages were not observed")
    else:
        if regular_after_second != (second,) or full_after_second != (first,):
            unmet.append("the first page did not enter BIN_FULL behind the second page")
        if regular_before_move != (second, first):
            unmet.append("local frees did not append the first page behind the second")
        if second_before_move is None or not (
            second_before_move[0] < second_before_move[1]
            and second_before_move[2] == second_before_move[0]
            and second_before_move[3:] == ("-", "-")
        ):
            unmet.append("the newer head was not expandable and without a free block")
        if first_before_move is None or not (
            first_before_move[0] == first_before_move[1] == per_page
            and first_before_move[2] == per_page - freed_from_first
            and first_before_move[4] != "-"
        ):
            unmet.append("the older page did not retain the expected local frees")
        if regular_after_move != (first, second) or selected != first:
            unmet.append("candidate search did not move and allocate from the older page")
    return {
        "regular_bin": regular_bin,
        "first_page": first,
        "second_page": second,
        "regular_after_second": regular_after_second,
        "full_after_second": full_after_second,
        "regular_before_move": regular_before_move,
        "regular_after_move": regular_after_move,
        "selected_page": selected,
        "second_before_move": second_before_move,
        "first_before_move": first_before_move,
        "unmet": unmet,
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
        if previous is not None and previous["size"] != size:
            # Both producers name a page by its slot and metadata address, so
            # a page released and re-created at the same slot within one
            # operation appears as a changed line with a new block size.
            events.setdefault(previous["bin"], set()).add("released")
            observed.add("created")
            previous = None
        if previous is not None:
            if previous["queue"] == BIN_FULL and queue != BIN_FULL:
                observed.add("unfull")
            if previous["expire"] > 0 and expire == 0 and used > previous["used"]:
                observed.add("retired-reuse")
        if expire > 0:
            observed.add("retired")
        pages[pid] = {"bin": home, "queue": queue, "used": used, "expire": expire, "size": size}
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
        workload_specs = {entry["id"]: entry for entry in contract["workloads"]}
        for name, text in workloads.items():
            workload = ARTIFACT_ROOT / f"{name}.workload"
            workload.write_text(text, encoding="utf-8")
            c_output = ARTIFACT_ROOT / f"{name}.c.trace"
            c_repeat = work / f"{name}.c.repeat.trace"
            rust_output = ARTIFACT_ROOT / f"{name}.rust.trace"
            c_options = contract["c_oracle"]["environment"]
            run_c_trace(c_build["binary"], workload, c_output, c_options)
            run_c_trace(c_build["binary"], workload, c_repeat, c_options)
            run_rust_trace(rust_binary, workload, rust_output)
            c_lines = c_output.read_text(encoding="utf-8").splitlines()
            rust_lines = rust_output.read_text(encoding="utf-8").splitlines()
            repeat_matches = c_repeat.read_bytes() == c_output.read_bytes()
            divergence = first_divergence(c_lines, rust_lines)
            digest = sha256_bytes(text.encode("utf-8"))
            specification = workload_specs[name]
            queue_witness = None
            if specification["generator"] == "queue-candidate-front":
                parameters = specification["parameters"]
                queue_witness = queue_candidate_front_witness(
                    c_lines, int(parameters["size"]), int(parameters["freed_from_first"])
                )
            results.append(
                {
                    "c_repeat_identical": repeat_matches,
                    "c_trace_sha256": run.sha256_file(c_output),
                    "coverage": trace_coverage(c_lines),
                    "divergence": divergence,
                    "id": name,
                    "queue_candidate_front": queue_witness,
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
        if result["queue_candidate_front"] is not None:
            unmet += [
                f"workload {result['id']}: {condition}"
                for condition in result["queue_candidate_front"]["unmet"]
            ]
    unmet += [f"coverage: {item}" for item in report["coverage_unmet"]]
    report["unmet"] = unmet
    report["status"] = "passed" if not unmet else "failed"
    return report


def run_queue_reorder_differential(
    contract: Mapping[str, Any], *, offline: bool, rust_binary: Path
) -> dict[str, Any]:
    fixture = contract["queue_reorder_differential"]
    paths: dict[str, Path] = {}
    for key in ("c_fixture", "runner"):
        value = fixture[key]
        if not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts:
            raise GateError(f"queue reorder {key} must stay inside the checkout")
        path = (ROOT / value).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise GateError(f"queue reorder {key} is missing from the checkout")
        paths[key] = path
    rust_test = fixture["rust_test"]
    if not isinstance(rust_test, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+", rust_test) is None:
        raise GateError("queue reorder Rust test is not a fully qualified test name")

    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    receipt_path = ARTIFACT_ROOT / "queue-reorder-runtime.json"
    c_trace_path = ARTIFACT_ROOT / "queue-reorder.c.trace"
    rust_log_path = ARTIFACT_ROOT / "queue-reorder.rust.log"
    rust_trace_path = ARTIFACT_ROOT / "queue-reorder.rust.trace"
    for stale in (c_trace_path, rust_log_path, rust_trace_path):
        stale.unlink(missing_ok=True)
    receipt: dict[str, Any] = {
        "c_fixture_sha256": run.sha256_file(paths["c_fixture"]),
        "runner_sha256": run.sha256_file(paths["runner"]),
        "rust_test": rust_test,
        "rust_source_sha256": run.sha256_file(ROOT / "crabc-mimalloc/src/page_queue.rs"),
    }
    unmet: list[str] = []
    with run.temporary_directory(prefix="crabc-mimalloc-m3-queue-reorder-") as temporary_name:
        work = Path(temporary_name)
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
        source = run.safe_extract(archive, work / "source", pin["archive_root"])
        receipt["archive_sha256"] = run.sha256_file(archive)
        c_binary = work / "m3-queue-reorder-c"
        build = run.command_record(
            (
                run.require_tool("musl-gcc"), "-std=c11", "-ffunction-sections",
                "-fdata-sections", "-Wl,--gc-sections", "-DMI_SHARED_LIB",
                "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
                *run.CONFIGURATION_PROFILES["release"],
                "-I", str(source / "include"), "-I", str(source / "src"),
                str(paths["c_fixture"]), "-o", str(c_binary),
            ),
            cwd=ROOT,
            timeout_seconds=600,
        )
        receipt["c_build"] = build
        if build["status"] != 0:
            unmet.append(f"pinned C queue fixture build exited {build['status']}")
        else:
            c = run.command_record((str(c_binary),), cwd=ROOT, timeout_seconds=600)
            rust = run.command_record(
                (str(rust_binary), rust_test, "--exact", "--nocapture", "--test-threads=1"),
                cwd=ROOT,
                timeout_seconds=600,
            )
            receipt["c_runtime"] = c
            receipt["rust_runtime"] = rust
            c_trace_path.write_text(str(c["stdout"]), encoding="utf-8")
            rust_log_path.write_text(str(rust["stdout"]) + "\n" + str(rust["stderr"]), encoding="utf-8")
            c_lines = str(c["stdout"]).splitlines()
            rust_lines = re.findall(r"M3Q [^\r\n]+", str(rust["stdout"]))
            rust_trace_path.write_text("\n".join(rust_lines) + "\n", encoding="utf-8")
            if c["status"] != 0:
                unmet.append(f"pinned C queue fixture exited {c['status']}")
            if rust["status"] != 0 or run.parse_rust_test_count(str(rust["stdout"]) + "\n" + str(rust["stderr"])) != 1:
                unmet.append("Rust queue fixture did not complete exactly one passing test")
            if c_lines != rust_lines:
                unmet.append("pinned C and Rust queue traces differ")
            expected = (
                ("start", "ABC", ""),
                ("first-full", "BC", "A"),
                ("middle-full", "C", "AB"),
                ("full-front", "C", "BA"),
                ("second-position", "CB", "A"),
                ("full-return", "CBA", ""),
            )
            if len(c_lines) != len(expected):
                unmet.append("pinned C queue trace did not contain six transitions")
            else:
                for line, (step, regular, full) in zip(c_lines, expected):
                    match = re.fullmatch(r"M3Q ([a-z-]+) regular=([ABC]*) full=([ABC]*) bytes=(\d+) pages=(\d+)", line)
                    if match is None:
                        unmet.append(f"malformed pinned C queue transition: {line}")
                        continue
                    observed_step, observed_regular, observed_full, bytes_text, pages_text = match.groups()
                    full_bytes = sum({"A": 128, "B": 192, "C": 256}[page] for page in observed_full)
                    if (
                        (observed_step, observed_regular, observed_full) != (step, regular, full)
                        or sorted(observed_regular + observed_full) != ["A", "B", "C"]
                        or int(bytes_text) != full_bytes
                        or int(pages_text) != 3
                    ):
                        unmet.append(f"unexpected pinned C queue transition: {line}")

    run.write_json(receipt_path, receipt)
    return {
        "archive_sha256": receipt.get("archive_sha256"),
        "c_fixture_sha256": receipt["c_fixture_sha256"],
        "c_trace_sha256": run.sha256_file(c_trace_path) if c_trace_path.is_file() else None,
        "raw_runtime_receipt": str(receipt_path),
        "runner_sha256": receipt["runner_sha256"],
        "rust_source_sha256": receipt["rust_source_sha256"],
        "rust_test": rust_test,
        "rust_trace_sha256": run.sha256_file(rust_trace_path) if rust_trace_path.is_file() else None,
        "status": "passed" if not unmet else "failed",
        "unmet": unmet,
    }


def run_queue_retirement_differential(contract: Mapping[str, Any]) -> dict[str, Any]:
    fixture = contract["queue_retirement_differential"]
    paths: dict[str, Path] = {}
    for key in ("c_fixture", "runner"):
        value = fixture[key]
        if not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts:
            raise GateError(f"queue retirement {key} must stay inside the checkout")
        path = (ROOT / value).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise GateError(f"queue retirement {key} is missing from the checkout")
        paths[key] = path
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    receipt_path = ARTIFACT_ROOT / "queue-retirement-runtime.json"
    trace_path = ARTIFACT_ROOT / "queue-retirement.trace"
    driver_path = ARTIFACT_ROOT / "queue-retirement-driver.json"
    c_trace_path = ARTIFACT_ROOT / "queue-retirement.c.trace"
    rust_trace_path = ARTIFACT_ROOT / "queue-retirement.rust.trace"
    for stale in (trace_path, driver_path, c_trace_path, rust_trace_path):
        stale.unlink(missing_ok=True)
    record = run.command_record(("python3", str(paths["runner"])), cwd=ROOT, timeout_seconds=1800)
    trace_path.write_text(str(record["stdout"]), encoding="utf-8")
    run.write_json(receipt_path, record)
    expected = (
        ("start", "ABC", "", "A", "RRR", 0, 3),
        ("retire-head", "BC", "", "B", "DRR", 0, 2),
        ("reuse-tail", "BCA", "", "B", "RRR", 0, 3),
        ("move-head", "CBA", "", "C", "RRR", 0, 3),
        ("full-head", "BA", "C", "B", "RRF", 256, 3),
        ("full-next", "A", "CB", "A", "RFF", 448, 3),
        ("retire-last-regular", "", "CB", "-", "DFF", 448, 2),
        ("reuse-from-full", "C", "B", "C", "DFR", 192, 2),
        ("retire-full", "C", "", "C", "DDR", 0, 1),
        ("retire-final", "", "", "-", "DDD", 0, 0),
    )
    lines = str(record["stdout"]).splitlines()
    parsed = []
    for line in (line for line in lines if line.startswith("M3R ")):
        match = re.fullmatch(
            r"M3R ([a-z-]+) regular=([ABC]*) full=([ABC]*) direct=([ABC-]) state=([RFD]{3}) bytes=(\d+) pages=(\d+)",
            line,
        )
        if match is None:
            break
        step, regular, full, direct, state, byte_count, page_count = match.groups()
        parsed.append((step, regular, full, direct, state, int(byte_count), int(page_count)))
    unmet = []
    if record["status"] != 0:
        unmet.append(f"queue retirement differential exited {record['status']}")
    if parsed != list(expected):
        unmet.append("pinned C/Rust queue retirement transitions differ from the source sequence")
    reachable = set(reachable_bin_ranges()) | {BIN_HUGE}
    sequences: dict[tuple[int, int], dict[str, Any]] = {}
    free_stages: dict[int, set[str]] = {}
    for line in lines:
        if line.startswith("M3R "):
            continue
        if line.startswith("M3B "):
            match = re.fullmatch(
                r"M3B bin=(\d+) size=(\d+) seed=(\d+) step=(\d+) action=([a-z-]+) page=([ABCS-]) regular=([ABC]*) full=([ABC]*) direct=([ABCS-]+) state=([RFD]{3}) bytes=(\d+) pages=(\d+) sentinel=([01])",
                line,
            )
            if match is None:
                unmet.append(f"malformed queue matrix state: {line}")
                continue
            bin_text, size_text, seed_text, step_text, action, page, regular, full, direct, state, bytes_text, pages_text, sentinel_text = match.groups()
            bin_index, size, seed, step = map(int, (bin_text, size_text, seed_text, step_text))
            key = (bin_index, seed)
            previous = sequences.get(key)
            if bin_index not in reachable or source_bin(size) != bin_index:
                unmet.append(f"queue matrix has an unreachable bin/size: {bin_index}/{size}")
            if action == "init":
                if previous is not None or step != 0:
                    unmet.append(f"queue matrix repeated or malformed initial state: {key}")
                previous = {"regular": "", "full": "", "sentinel": True, "step": -1, "size": size, "actions": set()}
            if previous is None:
                unmet.append(f"queue matrix has no initial state: {key}")
                continue
            expected_regular = str(previous["regular"])
            expected_full = str(previous["full"])
            expected_sentinel = bool(previous["sentinel"])
            source = "regular" if page in expected_regular else "full" if page in expected_full else None
            if action in {"push-head", "push-tail"}:
                if source is not None or page not in "ABC":
                    unmet.append(f"queue matrix pushes an attached/invalid page: {key}/{step}")
                expected_regular = page + expected_regular if action == "push-head" else expected_regular + page
            elif action in {"remove", "front", "transfer-tail", "transfer-second", "return-tail"}:
                if source is None:
                    unmet.append(f"queue matrix acts on a detached page: {key}/{step}")
                else:
                    source_names = expected_regular if source == "regular" else expected_full
                    source_names = source_names.replace(page, "")
                    destination_names = expected_full if source == "regular" else expected_regular
                    if action == "front":
                        source_names = page + source_names
                    elif action.startswith("transfer") or action == "return-tail":
                        if action == "return-tail" and source != "full":
                            unmet.append(f"queue matrix returns a page outside the full queue: {key}/{step}")
                        destination_names = (
                            destination_names[:1] + page + destination_names[1:]
                            if action == "transfer-second" else destination_names + page
                        )
                    if source == "regular":
                        expected_regular, expected_full = source_names, destination_names
                    else:
                        expected_full, expected_regular = source_names, destination_names
            elif action == "release-sentinel":
                if page != "S" or expected_regular or expected_full or not expected_sentinel:
                    unmet.append(f"queue matrix releases its sentinel with reachable pages: {key}/{step}")
                expected_sentinel = False
            elif action != "init":
                unmet.append(f"unknown queue transition: {action}")
            expected_state = "".join("R" if name in expected_regular else "F" if name in expected_full else "D" for name in "ABC")
            capacities = dict.fromkeys("ABC", 1) if bin_index == BIN_HUGE else {"A": 4, "B": 6, "C": 8}
            expected_bytes = sum(capacities[name] * size for name in expected_full)
            sentinel_bin = 2 if bin_index == 1 else 1
            expected_direct = "".join(
                "S" if source_bin(index * WORD) == sentinel_bin and expected_sentinel else
                expected_regular[0] if source_bin(index * WORD) == bin_index and expected_regular else "-"
                for index in range(SMALL_SIZE_MAX // WORD + 1)
            )
            if (
                (regular, full, direct, state) != (expected_regular, expected_full, expected_direct, expected_state)
                or len(set(regular + full)) != len(regular + full)
                or int(bytes_text) != expected_bytes
                or int(pages_text) != len(regular + full) + expected_sentinel
                or bool(int(sentinel_text)) != expected_sentinel
                or size != previous["size"] or step != previous["step"] + 1
            ):
                unmet.append(f"queue matrix violates its owner/cache/transition invariant: {key}/{step}")
            sequences[key] = {
                "regular": regular, "full": full, "sentinel": bool(int(sentinel_text)),
                "step": step, "size": size, "actions": previous["actions"] | {action},
            }
        elif line.startswith("M3F "):
            match = re.fullmatch(
                r"M3F size=(\d+) stage=([a-z-]+) capacity=(\d+) reserved=(\d+) used=(\d+) zero=([01]) free=([\d,-]+) local=([\d,-]+)", line,
            )
            if match is None:
                unmet.append(f"malformed free-list state: {line}")
                continue
            size_text, stage, capacity_text, reserved_text, used_text, zero, free_text, local_text = match.groups()
            size, capacity, reserved, used = map(int, (size_text, capacity_text, reserved_text, used_text))
            free = [] if free_text == "-" else [int(index) for index in free_text.split(",")]
            local = [] if local_text == "-" else [int(index) for index in local_text.split(",")]
            bin_index = source_bin(size)
            if (
                bin_index not in reachable - {BIN_HUGE} or not 0 <= used <= capacity <= reserved
                or used + len(free) + len(local) != capacity
                or len(set(free + local)) != len(free + local)
                or any(index < 0 or index >= capacity for index in free + local)
                or stage == "fresh" and (capacity != 0 or zero != "1")
                or stage == "exhausted" and (used != reserved or free or local or zero != "0")
            ):
                unmet.append(f"free-list matrix violates initialized ownership/counts: {size}/{stage}")
            free_stages.setdefault(bin_index, set()).add(stage)
        else:
            unmet.append(f"unrecognized local primitive trace record: {line}")
    required_actions = {"init", "push-head", "push-tail", "remove", "front", "transfer-tail", "transfer-second", "return-tail", "release-sentinel"}
    for bin_index in sorted(reachable):
        for seed in fixture["transition_seeds"]:
            sequence = sequences.get((bin_index, int(seed, 0)))
            if sequence is None:
                unmet.append(f"queue matrix did not execute bin {bin_index}, seed {seed}")
            elif sequence["sentinel"] or sequence["regular"] or sequence["full"] or not required_actions <= sequence["actions"]:
                unmet.append(f"queue matrix did not complete all transitions and release bin {bin_index}, seed {seed}")
    required_free_stages = {"fresh", "extend", "allocated", "local-two", "transfer", "both-lists", "false-force", "quick-preserve", "force-append", "reallocated", "local-many", "quick-transfer", "exhausted"}
    for bin_index in sorted(reachable - {BIN_HUGE}):
        if not required_free_stages <= free_stages.get(bin_index, set()):
            unmet.append(f"free-list matrix did not execute every source mode for bin {bin_index}")
    return {
        "c_fixture_sha256": run.sha256_file(paths["c_fixture"]),
        "c_trace_sha256": run.sha256_file(c_trace_path) if c_trace_path.is_file() else None,
        "raw_driver_receipt": str(driver_path) if driver_path.is_file() else None,
        "raw_runtime_receipt": str(receipt_path),
        "runner_sha256": run.sha256_file(paths["runner"]),
        "rust_source_sha256": run.sha256_file(ROOT / "crabc-mimalloc/src/page_queue.rs"),
        "rust_free_list_sha256": run.sha256_file(ROOT / "crabc-mimalloc/src/free_list.rs"),
        "rust_test": fixture["rust_test"],
        "rust_matrix_test": fixture["rust_matrix_test"],
        "rust_free_test": fixture["rust_free_test"],
        "rust_trace_sha256": run.sha256_file(rust_trace_path) if rust_trace_path.is_file() else None,
        "trace_sha256": run.sha256_file(trace_path),
        "status": "passed" if not unmet else "failed",
        "unmet": unmet,
    }


def owner_rust_test_binary(contract: Mapping[str, Any]) -> Path:
    rust = contract["persistent_owner_profile"]["rust_driver"]
    command = [
        "cargo", "test", "--locked", "--target", TARGET, "-p", "crabc-mimalloc",
        "--no-default-features", "--features", ",".join(rust["features"]),
        "--test", rust["target"], "--no-run", "--message-format=json",
    ]
    record = run.command_record(command, cwd=ROOT, timeout_seconds=3600)
    run.require_success(record, "Rust M3 persistent-owner trace test build")
    executables: list[str] = []
    for line in str(record["stdout"]).splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == rust["target"]
            and message.get("profile", {}).get("test")
            and message.get("executable")
        ):
            executables.append(message["executable"])
    if len(executables) != 1:
        raise GateError(f"expected one {rust['target']} test executable, found {executables}")
    return Path(executables[0])


def run_owner_rust_trace(
    binary: Path, test: str, owner: str, workload: Path, output: Path
) -> None:
    environment = {
        name: value for name, value in os.environ.items() if not name.lower().startswith("mimalloc_")
    }
    environment[OWNER_ENV] = owner
    environment[OWNER_WORKLOAD_ENV] = str(workload)
    environment[OWNER_OUTPUT_ENV] = str(output)
    record = run.command_record(
        (str(binary), test, "--exact", "--nocapture", "--test-threads=1"),
        cwd=ROOT,
        env=environment,
        timeout_seconds=3600,
    )
    run.require_success(record, f"Rust M3 {owner}-owner trace for {workload.name}")
    if run.parse_rust_test_count(str(record["stdout"]) + "\n" + str(record["stderr"])) != 1:
        raise GateError(f"Rust M3 {owner}-owner trace for {workload.name} did not run exactly one test")


def owner_coverage_unmet(coverage: Mapping[str, Any], requirements: Mapping[str, Any]) -> list[str]:
    """Checks the owner profile per page class. Aligned 16-byte requests
    route some bins' sizes to larger bins (source overallocation), so the
    per-bin matrix belongs to the local-engine differential instead."""

    unmet: list[str] = []
    bins = coverage["bins"]
    for name in requirements["page_classes"]:
        observed: set[str] = set()
        for bin_index, (_, high) in reachable_bin_ranges().items():
            if page_class(high) == name:
                observed.update(bins.get(str(bin_index), []))
        missing = sorted(set(requirements["page_class_events"]) - observed)
        if missing:
            unmet.append(f"{name} pages lack {', '.join(missing)}")
    for bin_index, names in bins.items():
        forbidden = sorted(set(requirements["forbidden_events"]) & set(names))
        if forbidden:
            unmet.append(f"bin {bin_index} reached {', '.join(forbidden)}")
    if coverage["admin_mini_collections"] < requirements["minimum_admin_mini_collections"]:
        unmet.append("generic administration mini-collections were not exercised")
    return unmet


def run_owner_differential(contract: Mapping[str, Any], *, offline: bool) -> dict[str, Any]:
    """Compares the production persistent owners with the pinned C default
    Theap: each (workload, owner) pair runs in fresh C, repeated C, and Rust
    processes and must match line by line."""

    profile = contract["persistent_owner_profile"]
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    workloads = generate_owner_workloads(contract)
    results: list[dict[str, Any]] = []
    with run.temporary_directory(prefix="crabc-mimalloc-m3-owner-trace-") as temporary_name:
        work = Path(temporary_name)
        c_build = build_c_driver(contract, work, offline)
        rust_binary = owner_rust_test_binary(contract)
        for name, text in workloads.items():
            workload = ARTIFACT_ROOT / f"{name}.workload"
            workload.write_text(text, encoding="utf-8")
            for owner in profile["owners"]:
                stem = f"{name}.{owner}"
                c_output = ARTIFACT_ROOT / f"{stem}.c.trace"
                c_repeat = work / f"{stem}.c.repeat.trace"
                rust_output = ARTIFACT_ROOT / f"{stem}.rust.trace"
                run_c_trace(c_build["binary"], workload, c_output, profile["c_environment"], owner)
                run_c_trace(c_build["binary"], workload, c_repeat, profile["c_environment"], owner)
                run_owner_rust_trace(rust_binary, profile["rust_driver"]["test"], owner, workload, rust_output)
                c_lines = c_output.read_text(encoding="utf-8").splitlines()
                rust_lines = rust_output.read_text(encoding="utf-8").splitlines()
                repeat_matches = c_repeat.read_bytes() == c_output.read_bytes()
                divergence = first_divergence(c_lines, rust_lines)
                results.append(
                    {
                        "c_repeat_identical": repeat_matches,
                        "c_trace_sha256": run.sha256_file(c_output),
                        "coverage": trace_coverage(c_lines),
                        "divergence": divergence,
                        "id": name,
                        "owner": owner,
                        "rust_trace_sha256": run.sha256_file(rust_output),
                        "status": "matched" if divergence is None and repeat_matches else "diverged",
                        "trace_lines": len(c_lines),
                        "workload_sha256": sha256_bytes(text.encode("utf-8")),
                    }
                )
        report: dict[str, Any] = {
            "archive_sha256": c_build["archive_sha256"],
            "c_driver_sha256": c_build["driver_sha256"],
            "rust_driver_sha256": run.sha256_file(OWNER_RUST_DRIVER_PATH),
            "trace_audit_sha256": run.sha256_file(OWNER_TRACE_AUDIT_PATH),
            "workloads": results,
        }
    unmet: list[str] = []
    for owner in profile["owners"]:
        coverage = merge_coverage(result["coverage"] for result in results if result["owner"] == owner)
        report.setdefault("coverage", {})[owner] = coverage
        unmet += [f"coverage ({owner} owner): {item}" for item in owner_coverage_unmet(coverage, profile["coverage_requirements"])]
    for result in results:
        if result["status"] != "matched":
            where = result["divergence"]["operation"] if result["divergence"] else "C repeat"
            unmet.insert(0, f"workload {result['id']} on the {result['owner']} owner diverged at {where}")
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
    miriflags = [*miri["miriflags"], f"-Zmiri-env-forward={FRESH_TEST_CHILD_ENV}"]
    environment["MIRIFLAGS"] = " ".join(miriflags)
    environment.pop(FRESH_TEST_CHILD_ENV, None)
    # Miri's sysroot builder creates a temporary Cargo package. Under the
    # launcher's `/workspace/.work/...` TMPDIR, Cargo would adopt it into the
    # checkout workspace and refuse it. The launcher bind-mounts the container
    # `/tmp` onto the same checkout-local work directory, so this path keeps
    # both the temporary package and the cached sysroot inside that boundary.
    environment["TMPDIR"] = "/tmp"
    # The pinned cargo-miri selects its `miri` cache through the absolute
    # XDG cache home; it does not recognize a MIRI_CACHE_DIR override.
    environment["XDG_CACHE_HOME"] = "/tmp/crabc-m3-miri-cache"
    # An explicit inherited sysroot would bypass the checkout-local cache.
    environment.pop("MIRI_SYSROOT", None)
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
    logs: list[str] = [f"### listing\n{json.dumps(listing['command'])}\n{listing['stdout']}\n{listing['stderr']}"]
    results: dict[str, Any] = {}
    unmet: list[str] = []
    passed: set[str] = set()
    # Each exact test starts a new isolated interpreter with cold globals.
    # The marked fixture enters directly: querying the native executable or
    # spawning another process is unavailable under Miri isolation. Forward
    # only its exact child marker; native execution keeps its exec boundary.
    for prefix, selected in groups.items():
        records: list[dict[str, Any]] = []
        for name in selected:
            child_environment = dict(environment, **{FRESH_TEST_CHILD_ENV: name})
            record = run.command_record(
                (*base, "--exact", "--test-threads=1", name),
                cwd=ROOT,
                env=child_environment,
                timeout_seconds=7200,
            )
            records.append(record)
            logs.append(f"### {prefix} {name}\n{json.dumps(record['command'])}\n"
                        f"MIRIFLAGS={child_environment['MIRIFLAGS']}\n"
                        f"{FRESH_TEST_CHILD_ENV}={name}\n{record['stdout']}\n{record['stderr']}")
        aggregate = {
            "status": next((record["status"] for record in records if record["status"] != 0), 0),
            "stdout": "\n".join(str(record["stdout"]) for record in records),
            "stderr": "\n".join(str(record["stderr"]) for record in records),
        }
        results[prefix] = summarize_group(prefix, selected, aggregate)
        unmet += [f"{prefix} {item}" for item in results[prefix]["unmet"]]
        output = str(aggregate["stdout"]) + "\n" + str(aggregate["stderr"])
        passed.update(name for name, outcome in TEST_RESULT.findall(output) if outcome == "ok")
    (ARTIFACT_ROOT / "miri.log").write_text("\n".join(logs), encoding="utf-8")
    for name in miri["required_tests"]:
        if name not in passed:
            unmet.append(f"required Miri test did not pass: {name}")
    return {
        "groups": results,
        "miriflags": miriflags,
        "passed": len(passed),
        "status": "passed" if not unmet else "failed",
        "unmet": unmet,
        "version": str(probe["stdout"]).strip(),
    }


# ---------------------------------------------------------------------------
# Gate.
# ---------------------------------------------------------------------------


def prerequisite_status(contract: Mapping[str, Any]) -> dict[str, Any]:
    # A completed historical receipt cannot qualify the source and compiler
    # selected for this execution. Keep its reported status while admitting
    # only clean, unchanged source and native image identities that match.
    source_state = run.runtime_ticket_zero_soak_source_state()
    execution = run.require_native_x86_64(require_image_identity=True)
    results: dict[str, Any] = {}
    unmet: list[str] = []
    for prerequisite in contract["milestone"]["prerequisites"]:
        path = run.WORK_ROOT / prerequisite["report"]
        status = "absent"
        receipt = None
        if path.is_file():
            try:
                receipt = json.loads(path.read_text(encoding="utf-8"))
                status = str(receipt["milestone"]["status"])
            except (OSError, KeyError, TypeError, json.JSONDecodeError):
                status = "unreadable"
        results[prerequisite["milestone"]] = {"report": prerequisite["report"], "status": status}
        subject = f"prerequisite {prerequisite['milestone'].upper()}"
        if status != "complete":
            unmet.append(f"{subject} is {status}, not complete")
        if status in {"absent", "unreadable"}:
            continue
        try:
            source = receipt["source"]
            if not isinstance(source, Mapping):
                raise run.HarnessError("source attestation is absent or invalid")
            attestation = run.runtime_ticket_zero_soak_source_attestation(source["before"], source["after"])
            if source != attestation:
                raise run.HarnessError("source attestation does not establish unchanged clean execution")
            if attestation["before"] != source_state:
                raise run.HarnessError("source differs from the current clean Git source")
        except (KeyError, TypeError, run.HarnessError) as error:
            unmet.append(f"{subject} source cannot qualify: {error}")
        try:
            run.validate_native_execution_provenance(
                receipt.get("native_execution_provenance"), expected_image_id=execution["image_id"]
            )
        except run.HarnessError as error:
            unmet.append(f"{subject} native execution cannot qualify: {error}")
    return {"milestones": results, "unmet": unmet}


def evaluate_gate(contract: Mapping[str, Any], checks: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    required_checks = {
        "local-trace-differential", "queue-reorder-differential", "queue-retirement-differential",
        "persistent-owner-trace-differential", "rust-unit-batch", "miri",
    }
    declared_checks = {check for component in contract["components"] for check in component["checks"]}
    omitted = required_checks - declared_checks
    if omitted:
        raise GateError(f"M3 components omit required checks: {', '.join(sorted(omitted))}")
    if not any(
        component["id"] == "page-queues" and "queue-reorder-differential" in component["checks"]
        for component in contract["components"]
    ):
        raise GateError("page queues must require the C/Rust reorder differential")
    if not any(
        component["id"] == "page-queues" and "queue-retirement-differential" in component["checks"]
        for component in contract["components"]
    ):
        raise GateError("page queues must require the C/Rust retirement differential")
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
        "--owner-only",
        action="store_true",
        help="run only the persistent-owner C/Rust trace differential (development; no gate report)",
    )
    parser.add_argument(
        "--miri-only",
        action="store_true",
        help="run only the Miri component (development; no gate report)",
    )
    parser.add_argument(
        "--queue-reorder-only",
        action="store_true",
        help="run only the pinned C/Rust page-queue reorder differential",
    )
    options = parser.parse_args(arguments)
    try:
        # Development subsets can inspect work in progress. Qualification
        # binds every local-engine observation to clean committed source and
        # the immutable compiler/oracle image selected by the native launcher.
        qualification = not any((
            options.queue_reorder_only, options.miri_only, options.owner_only, options.differential_only,
        ))
        source_before = run.runtime_ticket_zero_soak_source_state() if qualification else None
        contract = load_contract()
        provenance = run.require_native_x86_64(require_image_identity=qualification)
        lockfile = run.sha256_file(LOCKFILE)
        if options.queue_reorder_only:
            queue = run_queue_reorder_differential(
                contract, offline=options.offline, rust_binary=rust_test_binary()
            )
            run.write_json(QUEUE_REORDER_REPORT_PATH, {"queue_reorder_differential": queue, "provenance": provenance})
            print(QUEUE_REORDER_REPORT_PATH)
            if queue["status"] != "passed":
                print("\n".join(["M3 queue reorder differential failed:", *(f"  - {item}" for item in queue["unmet"])]), file=sys.stderr)
                return 1
            return 0
        if options.miri_only:
            miri = run_miri(contract)
            run.write_json(MIRI_REPORT_PATH, {"miri": miri, "provenance": provenance})
            print(MIRI_REPORT_PATH)
            if miri["status"] != "passed":
                print("\n".join(["M3 Miri component failed:", *(f"  - {item}" for item in miri["unmet"])]), file=sys.stderr)
                return 1
            return 0
        if options.owner_only:
            owner = run_owner_differential(contract, offline=options.offline)
            run.write_json(OWNER_REPORT_PATH, {"persistent_owner_differential": owner, "provenance": provenance})
            print(OWNER_REPORT_PATH)
            if owner["status"] != "passed":
                print("\n".join(["M3 persistent-owner trace differential failed:", *(f"  - {item}" for item in owner["unmet"])]), file=sys.stderr)
                return 1
            return 0
        differential = run_differential(contract, offline=options.offline)
        if options.differential_only:
            retirement = run_queue_retirement_differential(contract)
            report = {"differential": differential, "queue_retirement_differential": retirement, "provenance": provenance}
            run.write_json(DIFFERENTIAL_REPORT_PATH, report)
            print(DIFFERENTIAL_REPORT_PATH)
            if differential["status"] != "passed" or retirement["status"] != "passed":
                unmet = [*differential["unmet"], *retirement["unmet"]]
                print("\n".join(["M3 differential failed:", *(f"  - {item}" for item in unmet)]), file=sys.stderr)
                return 1
            return 0
        rust_binary = rust_test_binary()
        checks: dict[str, Any] = {
            "prerequisites": prerequisite_status(contract),
            "local-trace-differential": differential,
            "queue-reorder-differential": run_queue_reorder_differential(
                contract, offline=options.offline, rust_binary=rust_binary
            ),
            "queue-retirement-differential": run_queue_retirement_differential(contract),
            "persistent-owner-trace-differential": run_owner_differential(contract, offline=options.offline),
            "rust-unit-batch": run_unit_batch(contract, rust_binary),
            "miri": run_miri(contract),
        }
        if run.sha256_file(LOCKFILE) != lockfile:
            raise GateError("Cargo.lock changed during the --locked M3 gate")
        source = run.runtime_ticket_zero_soak_source_attestation(
            source_before, run.runtime_ticket_zero_soak_source_state()
        )
        native_execution = run.native_execution_attestation(
            provenance, run.require_native_x86_64(require_image_identity=True)
        )
        gate = evaluate_gate(contract, checks)
        report = {
            "checks": checks,
            "contract_sha256": run.sha256_file(CONTRACT_PATH),
            "format": 1,
            "kind": "mimalloc-x86_64-m3-local-engine-gate",
            "milestone": {"id": "m3", "status": gate["status"]},
            "gate": gate,
            "provenance": {key: provenance[key] for key in ("execution_mode", "host_architecture")},
            "native_execution_provenance": native_execution,
            "source": source,
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
