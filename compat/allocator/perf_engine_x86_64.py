#!/usr/bin/env python3
"""Native x86-64 allocator engine development performance measurements.

This runner builds one source-shared C workload fixture
(``perf-x86_64/engine-fixture.c``) twice, each time linked with exactly one
opaque backend behind ``perf-x86_64/engine-api.h``:

* ``pinned_c``: the SHA-256-verified pinned mimalloc v3.5.0 C source;
* ``rust_engine``: crabc-mimalloc's persistent per-thread source owners
  through the hidden ``__crabc_runtime`` entry points that crabc-libc's
  ``native-mimalloc-shadow`` selection calls.

Both lanes are static non-PIE musl 1.2.6 executables built from one
byte-identical fixture object. Samples alternate between lanes in a recorded
randomized pair order. Every raw batch record (wall ns and allocator calls),
process rusage, and /proc memory snapshot is retained in the JSON report with
source, toolchain, host, load, and artifact provenance.

``--set architecture`` measures the rows behind plan.md's early architecture
sanity check (single-thread Rust/C throughput and independent four-worker
scaling); ``--set matrix`` measures the complete equivalent workload/memory
matrix. Every timed row records throughput, the per-process p99 batch cost
(the slow-batch tail), the exec image's peak RSS (``VmHWM`` read at a
ptrace exit stop) and its peak-state PSS, read while the fixture holds its
largest live batch state at an untimed READY_PEAK pause after the last
timed batch (``--no-peak-hook`` omits the pause; ``--peak-hook-ab``
measures each lane's timed rows with and without it in adjacent process
pairs and records both distributions and their paired ratio).
Every memory row records peak RSS and live PSS.

Each report also records raw host-contention evidence (load average,
/proc/stat CPU windows before, between and after rows, visible competing
processes, cpufreq policy and container CPU quota/throttling) and classifies
it under the documented ``UNCONTENDED_*`` thresholds. A report records no
gate verdict. ``validate_qualified_full_report`` decides whether one report
is a qualified full report (``--full --set matrix``, every row measured, a
clean sealed checkout, an uncontended host) by recomputing everything from
the raw data; the ``allocator-m9`` gate and ``performance.release`` consume
it.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
import platform
import random
import re
import select
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
ALLOCATOR_ROOT = ROOT / "compat/allocator"
FIXTURE_ROOT = ALLOCATOR_ROOT / "perf-x86_64"
MANIFEST = FIXTURE_ROOT / "engine-matrix-v3.5.0.json"
HEADER = FIXTURE_ROOT / "engine-api.h"
FIXTURE = FIXTURE_ROOT / "engine-fixture.c"
C_BACKEND = FIXTURE_ROOT / "engine-c-backend.c"
RUST_BACKEND = FIXTURE_ROOT / "engine-rust-backend.rs"
# `compat/reports` is the runner's bind mount of the host checkout's
# `.work/allocator-x86_64/reports`.
REPORT_ROOT = ROOT / "compat/reports/allocator/x86_64/perf-engine"

SCHEMA = 3
KIND = "crabc-mimalloc-x86_64-engine-development-performance"
RUST_TARGET = "x86_64-unknown-linux-musl"
LANES = ("pinned_c", "rust_engine")
# `destruction` measures first-class heap and child-subprocess destruction
# through the optional engine-api.h entries; it is separate from the matrix
# until every backend defines them.
ROW_SETS = ("architecture", "matrix", "destruction")
TIMED_WORKLOADS = frozenset(
    {
        "alloc_free",
        "alloc_batch",
        "calloc_free",
        "aligned_free",
        "realloc_grow",
        "realloc_inplace",
        "usable_size",
        "churn",
        "churn_scaling",
        "local_scaling",
        "remote_free",
        "thread_churn",
        "heap_destroy",
        "subproc_destroy",
    }
)
MEMORY_WORKLOADS = frozenset({"memory_live", "memory_churn"})
PARAMETER_KEYS = frozenset(
    {"size", "max_size", "alignment", "count", "workers", "live", "total", "iterations", "batches", "seed"}
)
BOOTSTRAP_RESAMPLES = 2_000


def _load_shared_helpers():
    """Reuse the archive, ELF, process, and /proc helpers of perf_x86_64.py."""

    path = ALLOCATOR_ROOT / "perf_x86_64.py"
    spec = importlib.util.spec_from_file_location("crabc_allocator_perf_x86_64_shared", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


shared = _load_shared_helpers()
HarnessError = shared.HarnessError
sha256_file = shared.sha256_file
file_record = shared.file_record
artifact_record = shared.artifact_record
command_record = shared.command_record
require_success = shared.require_success
require_tool = shared.require_tool
validate_label = shared.validate_label


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Write a report atomically, readable by the invoking host user."""

    shared.atomic_write_json(path, value)
    os.chmod(path, 0o644)


# ---- manifest ---------------------------------------------------------------


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"cannot read engine performance manifest: {error}") from error
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    """Fail closed on a matrix the fixture cannot run as declared."""

    if manifest.get("schema") != "crabc-mimalloc-x86_64-engine-performance-matrix" or manifest.get("format") != 2:
        raise HarnessError("engine performance manifest schema changed")
    if set(manifest.get("lanes", {})) != set(LANES):
        raise HarnessError("engine performance manifest must declare exactly the pinned_c and rust_engine lanes")
    modes = manifest.get("modes")
    if not isinstance(modes, Mapping) or set(modes) != {"smoke", "full"}:
        raise HarnessError("engine performance manifest must declare smoke and full modes")
    for name, mode in modes.items():
        for key in ("samples", "warmup_processes", "batch_divisor"):
            value = mode.get(key) if isinstance(mode, Mapping) else None
            if type(value) is not int or value < (0 if key == "warmup_processes" else 1):
                raise HarnessError(f"engine performance mode {name}.{key} is invalid")
    rows_by_name: dict[str, Mapping[str, Any]] = {}
    for group, allowed in (("rows", TIMED_WORKLOADS), ("memory_rows", MEMORY_WORKLOADS)):
        rows = manifest.get(group)
        if not isinstance(rows, list) or not rows:
            raise HarnessError(f"engine performance manifest lacks {group}")
        for row in rows:
            name = row.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name) or name in rows_by_name:
                raise HarnessError(f"engine performance row name is invalid or duplicated: {name!r}")
            rows_by_name[name] = row
            if row.get("workload") not in allowed:
                raise HarnessError(f"engine performance row {name} has an unsupported workload")
            params = row.get("params")
            if not isinstance(params, Mapping) or not set(params) <= PARAMETER_KEYS:
                raise HarnessError(f"engine performance row {name} has unsupported parameters")
            if not all(type(value) is int and value >= 0 for value in params.values()):
                raise HarnessError(f"engine performance row {name} has a non-integer parameter")
            sets = row.get("sets")
            if not isinstance(sets, list) or not sets or not set(sets) <= set(ROW_SETS):
                raise HarnessError(f"engine performance row {name} has invalid sets")
    critical = manifest.get("critical_rows", {}).get("rows") if isinstance(manifest.get("critical_rows"), Mapping) else None
    if not isinstance(critical, Mapping) or not critical:
        raise HarnessError("engine performance manifest lacks its critical-row roster")
    timed_names = {row["name"]: row for row in manifest["rows"]}
    for name, rationale in critical.items():
        if name not in timed_names or "matrix" not in timed_names[name]["sets"]:
            raise HarnessError(f"critical row {name} is not a timed matrix row")
        if not isinstance(rationale, str) or not rationale:
            raise HarnessError(f"critical row {name} lacks its rationale")
    architecture = manifest.get("architecture_rows")
    if not isinstance(architecture, Mapping):
        raise HarnessError("engine performance manifest lacks its architecture rows")
    for key, workers in (("single_thread", 1), ("four_thread", 4)):
        row = rows_by_name.get(architecture.get(key))
        if row is None or "architecture" not in row["sets"] or row["workload"] != "local_scaling":
            raise HarnessError(f"architecture {key} row must be an architecture-set local_scaling row")
        if row["params"].get("workers") != workers:
            raise HarnessError(f"architecture {key} row must use {workers} worker(s)")
        if row["params"].get("size") != rows_by_name[architecture["single_thread"]]["params"].get("size"):
            raise HarnessError("architecture rows must measure one request size")


def selected_rows(manifest: Mapping[str, Any], row_set: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if row_set not in ROW_SETS:
        raise HarnessError(f"unknown row set: {row_set}")
    timed = [dict(row) for row in manifest["rows"] if row_set in row["sets"]]
    memory = [dict(row) for row in manifest["memory_rows"] if row_set in row["sets"]]
    return timed, memory


def row_thread_count(row: Mapping[str, Any]) -> int:
    """CPUs a row pins: one per worker, two per remote-free pair."""

    workers = int(row["params"].get("workers", 1))
    if row["workload"] == "remote_free":
        return 2 * workers
    if row["workload"] in {"local_scaling", "churn_scaling", "thread_churn"}:
        return workers
    return 1


def expected_batches(row: Mapping[str, Any], batch_divisor: int) -> int:
    return max(1, int(row["params"].get("batches", 1)) // batch_divisor)


def fixture_arguments(row: Mapping[str, Any], *, batch_divisor: int, cpus: Sequence[int]) -> list[str]:
    params = dict(row["params"])
    if "batches" in params:
        params["batches"] = expected_batches(row, batch_divisor)
    arguments = [row["workload"]]
    arguments.extend(f"{key}={params[key]}" for key in sorted(params))
    if row["workload"] in {"local_scaling", "churn_scaling", "remote_free"}:
        arguments.append("cpus=" + ",".join(str(cpu) for cpu in cpus))
    return arguments


# ---- fixture output ---------------------------------------------------------


BATCH_RECORD = re.compile(r"batch ns=([0-9]+) cpu_ns=([0-9]+) ops=([0-9]+)")


def parse_timed_output(output: str, *, expected_batches: int) -> list[dict[str, int]]:
    """Accept exactly the fixture's address-free batch grammar."""

    lines = output.splitlines()
    if not lines or lines[-1] != "ok":
        raise HarnessError("fixture output lacks its terminal ok record")
    batches: list[dict[str, int]] = []
    for line in lines[:-1]:
        match = BATCH_RECORD.fullmatch(line)
        if match is None:
            raise HarnessError(f"fixture output contains an unexpected record: {line!r}")
        nanoseconds, cpu_nanoseconds, operations = (int(group) for group in match.groups())
        if nanoseconds <= 0 or cpu_nanoseconds <= 0 or operations <= 0:
            raise HarnessError("fixture batch record must have positive time, CPU time, and operation count")
        batches.append({"ns": nanoseconds, "cpu_ns": cpu_nanoseconds, "ops": operations})
    if len(batches) != expected_batches:
        raise HarnessError(f"fixture expected {expected_batches} batch records, found {len(batches)}")
    return batches


# ---- process execution ------------------------------------------------------


def clean_environment() -> dict[str, str]:
    """Both lanes see the same minimal environment and default options."""

    return {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"}


PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACEEXIT = 0x40
PTRACE_O_EXITKILL = 0x100000
PTRACE_EVENT_EXIT = 6
_PTRACE = None


def _ptrace_function():
    global _PTRACE
    if _PTRACE is None:
        function = ctypes.CDLL(None, use_errno=True).ptrace
        function.restype = ctypes.c_long
        function.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
        _PTRACE = function
    return _PTRACE


def ptrace(request: int, pid: int, data: int = 0) -> None:
    """Call ptrace(2); the exit trace uses only TRACEME, SETOPTIONS and CONT."""

    function = _ptrace_function()
    ctypes.set_errno(0)
    if function(request, pid, None, ctypes.c_void_p(data)) == -1 and ctypes.get_errno() != 0:
        raise HarnessError(f"ptrace request {request:#x} on {pid} failed: {os.strerror(ctypes.get_errno())}")


def spawn(
    binary: Path | tuple[Path, str],
    arguments: Sequence[str],
    *,
    cpus: Sequence[int],
    stdout_path: Path,
    stderr_path: Path,
    pass_fds: Sequence[int] = (),
    trace_exit: bool = False,
) -> int:
    # A (root, path) executable runs chrooted into an installed product's
    # runtime tree, where its PT_INTERP and libc resolve.
    root, program = (binary if isinstance(binary, tuple) else (None, str(binary)))
    if trace_exit:
        _ptrace_function()  # resolve libc's ptrace before fork, not in the child
    pid = os.fork()
    if pid == 0:
        try:
            if trace_exit:
                ptrace(PTRACE_TRACEME, 0)
            os.sched_setaffinity(0, set(cpus))
            stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            os.close(stdout)
            os.close(stderr)
            for descriptor in pass_fds:
                os.set_inheritable(descriptor, True)
            if root is not None:
                os.chroot(root)
                os.chdir("/")
            os.execve(program, [program, *arguments], clean_environment())
        except BaseException as error:  # noqa: BLE001 - child must never return
            os.write(2, f"fixture exec failure: {error}\n".encode("utf-8", errors="replace"))
            os._exit(127)
    return pid


def exit_memory_snapshot(pid: int) -> dict[str, Any]:
    """The exec image's memory at its exit stop, before the kernel drops its mm."""

    proc = Path("/proc") / str(pid)
    try:
        status = (proc / "status").read_text(encoding="utf-8")
        rollup = (proc / "smaps_rollup").read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError(f"cannot snapshot the exiting fixture's memory: {error}") from error
    return {"status": parse_status(status), "smaps_rollup": shared.parse_smaps_rollup(rollup)}


class PeakProbe:
    """The parent side of a timed fixture's one READY_PEAK pause."""

    def __init__(self, ready: int, control: int) -> None:
        self.ready, self.control = ready, control
        self.received = bytearray()
        self.snapshot: dict[str, Any] | None = None
        self.closed = False

    def poll(self, pid: int, wait: float) -> bool:
        """Serve the pause if it is pending; True when this call made progress."""

        if self.closed or self.snapshot is not None:
            return False
        ready, _, _ = select.select([self.ready], [], [], wait)
        if not ready:
            return False
        chunk = os.read(self.ready, 64)
        if not chunk:
            self.closed = True
            return True
        self.received.extend(chunk)
        if self.received.endswith(b"\n"):
            if bytes(self.received) != b"READY_PEAK\n":
                raise HarnessError(f"timed fixture wrote {bytes(self.received)!r}, not READY_PEAK")
            # The peak state is live and every participant is parked.
            self.snapshot = memory_snapshot(pid)
            os.write(self.control, b"1")
        return True


def wait_traced_exit(
    pid: int, timeout: float, peak: PeakProbe | None = None
) -> tuple[int, Any, bool, dict[str, Any] | None]:
    """Reap a PTRACE_TRACEME child, snapshotting it once at PTRACE_EVENT_EXIT.

    Only the initial thread is traced (no TRACECLONE), and it stops only at
    exec and at exit, so no timed batch is interrupted. ``ru_maxrss`` cannot
    serve as the peak: Linux folds the forked harness image's high-water mark
    into it at exec, so the exec image's own ``VmHWM`` is read at the exit
    stop instead.
    """

    deadline = time.monotonic() + timeout
    exec_stop_seen = False
    snapshot: dict[str, Any] | None = None
    while True:
        try:
            if peak is not None and peak.poll(pid, 0):
                continue
        except (HarnessError, OSError):
            os.kill(pid, signal.SIGKILL)
            while os.WIFSTOPPED(os.wait4(pid, 0)[1]):
                pass
            raise
        completed_pid, status, usage = os.wait4(pid, os.WNOHANG)
        if completed_pid == pid:
            if not os.WIFSTOPPED(status):
                return status, usage, False, snapshot
            if status >> 8 == (signal.SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
                snapshot = exit_memory_snapshot(pid)
                ptrace(PTRACE_CONT, pid)
            elif not exec_stop_seen and os.WSTOPSIG(status) == signal.SIGTRAP:
                exec_stop_seen = True
                ptrace(PTRACE_SETOPTIONS, pid, PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL)
                ptrace(PTRACE_CONT, pid)
            else:
                ptrace(PTRACE_CONT, pid, os.WSTOPSIG(status))
            continue
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            while True:
                _, status, usage = os.wait4(pid, 0)
                if not os.WIFSTOPPED(status):
                    return status, usage, True, snapshot
        if peak is None or peak.snapshot is not None or peak.closed:
            time.sleep(0.001)
        else:
            peak.poll(pid, 0.001)


def finish_process(
    pid: int, started: int, timeout: float, stdout_path: Path, stderr_path: Path, *, traced: bool = False,
    peak: PeakProbe | None = None,
) -> tuple[dict[str, Any], str]:
    exit_memory = None
    if traced:
        status, usage, timed_out, exit_memory = wait_traced_exit(pid, timeout, peak)
    else:
        status, usage, timed_out = shared.wait_with_rusage(pid, timeout)
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    process = {
        "elapsed_wall_ns": time.monotonic_ns() - started,
        "resources": shared.rusage_record(usage),
        "status": shared.status_record(status, timed_out),
    }
    if traced:
        process["exit_memory"] = exit_memory
    if process["status"] != {"code": 0, "kind": "exit"} or stderr:
        raise HarnessError(
            f"fixture failed: status={process['status']} stderr={stderr[:512]!r} stdout={stdout[-512:]!r}"
        )
    return process, stdout


def run_timed_sample(
    binary: Path,
    row: Mapping[str, Any],
    *,
    batch_divisor: int,
    cpus: Sequence[int],
    timeout: float,
    scratch: Path,
    sample_name: str,
    peak_hook: bool = True,
) -> dict[str, Any]:
    """One timed process; with ``peak_hook`` it also serves the untimed READY_PEAK pause."""

    arguments = fixture_arguments(row, batch_divisor=batch_divisor, cpus=cpus)
    stdout_path = scratch / f"{sample_name}.stdout"
    stderr_path = scratch / f"{sample_name}.stderr"
    descriptors: list[int] = []
    probe = None
    if peak_hook:
        ready_read, ready_write = os.pipe()
        control_read, control_write = os.pipe()
        descriptors = [ready_read, ready_write, control_read, control_write]
        arguments.extend((f"ready_fd={ready_write}", f"control_fd={control_read}"))
        probe = PeakProbe(ready_read, control_write)
    started = time.monotonic_ns()
    try:
        pid = spawn(binary, arguments, cpus=cpus, stdout_path=stdout_path, stderr_path=stderr_path, trace_exit=True,
                    pass_fds=(ready_write, control_read) if peak_hook else ())
        if peak_hook:
            os.close(ready_write)
            os.close(control_read)
            descriptors = [ready_read, control_write]
        process, stdout = finish_process(pid, started, timeout, stdout_path, stderr_path, traced=True, peak=probe)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    if process["exit_memory"] is None:
        raise HarnessError("fixture exited without its PTRACE_EVENT_EXIT memory snapshot")
    batches = parse_timed_output(stdout, expected_batches=expected_batches(row, batch_divisor))
    sample = {"arguments": arguments, "cpus": list(cpus), "process": process, "batches": batches}
    if peak_hook:
        if probe.snapshot is None:
            raise HarnessError("timed fixture exited without its READY_PEAK pause")
        sample["peak_state"] = probe.snapshot
    return sample


def read_ready(descriptor: int, expected: bytes, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    received = bytearray()
    while not received.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HarnessError(f"memory fixture timed out before {expected!r}")
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(descriptor, 1)
        if not chunk:
            raise HarnessError(f"memory fixture closed its readiness pipe before {expected!r}")
        received.extend(chunk)
    if bytes(received) != expected:
        raise HarnessError(f"memory fixture expected {expected!r}, observed {bytes(received)!r}")


STATUS_FIELDS = {"VmRSS": "vm_rss_kib", "VmHWM": "vm_hwm_kib", "VmSize": "vm_size_kib", "VmPeak": "vm_peak_kib"}


def parse_status(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for source, destination in STATUS_FIELDS.items():
        match = re.search(rf"(?m)^{source}:\s+([0-9]+)\s+kB$", text)
        if match is None:
            raise HarnessError(f"/proc status lacks {source}")
        result[destination] = int(match.group(1))
    return result


def memory_snapshot(pid: int) -> dict[str, Any]:
    proc = Path("/proc") / str(pid)
    try:
        status = (proc / "status").read_text(encoding="utf-8")
        rollup = (proc / "smaps_rollup").read_text(encoding="utf-8")
        maps = (proc / "maps").read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError(f"cannot snapshot live fixture memory: {error}") from error
    return {
        "maps": shared.maps_record(maps),
        "smaps_rollup": shared.parse_smaps_rollup(rollup),
        "status": parse_status(status),
    }


def run_memory_sample(
    binary: Path,
    row: Mapping[str, Any],
    *,
    batch_divisor: int,
    cpus: Sequence[int],
    timeout: float,
    scratch: Path,
    sample_name: str,
) -> dict[str, Any]:
    ready_read, ready_write = os.pipe()
    control_read, control_write = os.pipe()
    arguments = fixture_arguments(row, batch_divisor=batch_divisor, cpus=cpus)
    arguments.extend((f"ready_fd={ready_write}", f"control_fd={control_read}"))
    stdout_path = scratch / f"{sample_name}.stdout"
    stderr_path = scratch / f"{sample_name}.stderr"
    started = time.monotonic_ns()
    pid = spawn(
        binary,
        arguments,
        cpus=cpus,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        pass_fds=(ready_write, control_read),
    )
    os.close(ready_write)
    os.close(control_read)
    snapshots: dict[str, Any] = {}
    reaped = False
    try:
        for phase, line in (("post_init", b"READY_INIT\n"), ("live", b"READY_LIVE\n"), ("freed", b"READY_FREED\n")):
            read_ready(ready_read, line, timeout)
            snapshots[phase] = memory_snapshot(pid)
            os.write(control_write, b"1")
        process, stdout = finish_process(pid, started, timeout, stdout_path, stderr_path)
        reaped = True
    finally:
        os.close(ready_read)
        os.close(control_write)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
    if stdout != "ok\n":
        raise HarnessError(f"memory fixture output is not exactly ok: {stdout[:256]!r}")
    return {"arguments": arguments, "cpus": list(cpus), "process": process, "snapshots": snapshots}


# ---- statistics -------------------------------------------------------------


def sample_ns_per_op(sample: Mapping[str, Any]) -> float:
    """Median batch cost of one fixture process, in wall ns per allocator call.

    A multi-worker batch counts every worker's calls inside one wall
    interval, so this is the inverse of aggregate throughput.
    """

    return statistics.median(batch["ns"] / batch["ops"] for batch in sample["batches"])


def sample_cpu_ns_per_op(sample: Mapping[str, Any]) -> float:
    """Median batch thread-CPU cost per allocator call, summed over participants.

    Unlike wall time this excludes preemption by other host load, but it
    still includes lock, shared-cache-line, and spinning costs, so it is the
    contention-robust signal for independent-owner scaling.
    """

    return statistics.median(batch["cpu_ns"] / batch["ops"] for batch in sample["batches"])


def quantile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def paired_bootstrap(
    reference: Sequence[float], candidate: Sequence[float], *, seed: int, resamples: int | None = None
) -> list[float]:
    """Candidate/reference median ratios from paired process resamples."""

    resamples = BOOTSTRAP_RESAMPLES if resamples is None else resamples
    if not reference or len(reference) != len(candidate) or min(reference) <= 0 or min(candidate) <= 0:
        raise HarnessError("paired bootstrap requires equal positive sample lists")
    source = random.Random(seed)
    count = len(reference)
    ratios = []
    for _ in range(resamples):
        indices = [source.randrange(count) for _ in range(count)]
        ratios.append(
            statistics.median(candidate[index] for index in indices)
            / statistics.median(reference[index] for index in indices)
        )
    return ratios


def sample_batch_p99_ns_per_op(sample: Mapping[str, Any]) -> float:
    """One process's p99 batch cost, in wall ns per allocator call.

    The fixture times batches, never single operations, so this tail is the
    slow-batch tail (periodic collection, purge, page and thread-lifecycle
    work that concentrates in some batches), not a per-call latency.
    """

    return quantile([batch["ns"] / batch["ops"] for batch in sample["batches"]], 0.99)


def sample_peak_pss_kib(sample: Mapping[str, Any]) -> int | None:
    """PSS at the untimed peak-state pause, or None without the peak hook."""

    state = sample.get("peak_state")
    return int(state["smaps_rollup"]["pss_kib"]) if isinstance(state, Mapping) else None


def sample_peak_rss_kib(sample: Mapping[str, Any]) -> int:
    """The exec image's own RSS high-water mark, read at its exit stop."""

    memory = sample.get("process", {}).get("exit_memory")
    if not isinstance(memory, Mapping):
        raise HarnessError("timed sample lacks its exit-stop memory snapshot")
    return int(memory["status"]["vm_hwm_kib"])


# Seeds of the tail and memory bootstraps derive from the row seed, so one
# recorded seed reproduces every interval of a row.
TAIL_SEED = 0x7A11
RSS_SEED = 0x5255
PSS_SEED = 0x5053


def ratio_distribution(reference: Sequence[float], candidate: Sequence[float], *, seed: int) -> list[float] | None:
    """Bootstrap candidate/reference median ratios; None for a zero reference."""

    if not reference or min(reference) <= 0 or min(candidate) <= 0:
        return None
    return paired_bootstrap(reference, candidate, seed=seed)


def ratio_summary(reference: Sequence[float], candidate: Sequence[float], *, seed: int) -> dict[str, Any]:
    reference_median = statistics.median(reference)
    candidate_median = statistics.median(candidate)
    distribution = ratio_distribution(reference, candidate, seed=seed)
    return {
        "pinned_c_median": reference_median,
        "rust_engine_median": candidate_median,
        "ratio_rust_over_c": {
            "median": candidate_median / reference_median if reference_median > 0 else None,
            "bootstrap_95th_percentile": quantile(distribution, 0.95) if distribution else None,
        },
    }


def throughput_distribution(c_samples: Sequence[Mapping[str, Any]], rust_samples: Sequence[Mapping[str, Any]], *, seed: int) -> list[float]:
    c_cost = [sample_ns_per_op(sample) for sample in c_samples]
    rust_cost = [sample_ns_per_op(sample) for sample in rust_samples]
    return [1.0 / ratio for ratio in paired_bootstrap(c_cost, rust_cost, seed=seed)]


def throughput_comparison(
    c_samples: Sequence[Mapping[str, Any]], rust_samples: Sequence[Mapping[str, Any]], *, seed: int
) -> dict[str, Any]:
    """Indicative Rust/C throughput (the inverse ratio of per-call cost),
    slow-batch p99 cost, and the exec image's peak RSS."""

    c_cost = [sample_ns_per_op(sample) for sample in c_samples]
    rust_cost = [sample_ns_per_op(sample) for sample in rust_samples]
    throughput = throughput_distribution(c_samples, rust_samples, seed=seed)
    c_cpu = [sample_cpu_ns_per_op(sample) for sample in c_samples]
    rust_cpu = [sample_cpu_ns_per_op(sample) for sample in rust_samples]
    return {
        "median_ns_per_op": {"pinned_c": statistics.median(c_cost), "rust_engine": statistics.median(rust_cost)},
        "median_cpu_ns_per_op": {"pinned_c": statistics.median(c_cpu), "rust_engine": statistics.median(rust_cpu)},
        "cpu_throughput_ratio_rust_over_c": statistics.median(c_cpu) / statistics.median(rust_cpu),
        "throughput_ratio_rust_over_c": {
            "median": statistics.median(c_cost) / statistics.median(rust_cost),
            "bootstrap_5th_percentile": quantile(throughput, 0.05),
            "bootstrap_95th_percentile": quantile(throughput, 0.95),
        },
        "batch_p99_ns_per_op": ratio_summary(
            [sample_batch_p99_ns_per_op(sample) for sample in c_samples],
            [sample_batch_p99_ns_per_op(sample) for sample in rust_samples], seed=seed ^ TAIL_SEED),
        "peak_rss_kib": ratio_summary(
            [sample_peak_rss_kib(sample) for sample in c_samples],
            [sample_peak_rss_kib(sample) for sample in rust_samples], seed=seed ^ RSS_SEED),
        "peak_pss_kib": peak_pss_summary(c_samples, rust_samples, seed=seed),
        "bootstrap": {"resamples": BOOTSTRAP_RESAMPLES, "seed": seed},
    }


def peak_pss_values(samples: Sequence[Mapping[str, Any]]) -> list[int] | None:
    values = [sample_peak_pss_kib(sample) for sample in samples]
    return None if not values or None in values else values


def peak_pss_summary(
    c_samples: Sequence[Mapping[str, Any]], rust_samples: Sequence[Mapping[str, Any]], *, seed: int
) -> dict[str, Any] | None:
    c_values, rust_values = peak_pss_values(c_samples), peak_pss_values(rust_samples)
    if c_values is None or rust_values is None:
        return None
    return ratio_summary(c_values, rust_values, seed=seed ^ PSS_SEED)


def resource_summary(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    fields = (
        "minor_faults", "major_faults", "voluntary_context_switches", "involuntary_context_switches",
        "max_rss_kib", "user_cpu_ns", "system_cpu_ns",
    )
    return {
        field: shared.numeric_summary([int(sample["process"]["resources"][field]) for sample in samples])
        for field in fields
    }


MEMORY_METRICS = {
    "peak_rss_kib": ("live", "status", "vm_hwm_kib"),
    "live_pss_kib": ("live", "smaps_rollup", "pss_kib"),
    "live_rss_kib": ("live", "smaps_rollup", "rss_kib"),
    "freed_rss_kib": ("freed", "smaps_rollup", "rss_kib"),
    "live_mapping_count": ("live", "maps", "mapping_count"),
}


# Memory-row metrics that carry a bootstrap upper bound: the promotion
# table's peak RSS and PSS.
MEMORY_BOUND_SEEDS = {"peak_rss_kib": RSS_SEED, "live_pss_kib": PSS_SEED}


def memory_values(samples: Sequence[Mapping[str, Any]], metric: str) -> list[int]:
    phase, group, field = MEMORY_METRICS[metric]
    return [int(sample["snapshots"][phase][group][field]) for sample in samples]


def memory_comparison(
    c_samples: Sequence[Mapping[str, Any]], rust_samples: Sequence[Mapping[str, Any]], *, seed: int
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for metric in MEMORY_METRICS:
        c_values, rust_values = memory_values(c_samples, metric), memory_values(rust_samples, metric)
        c_median, rust_median = statistics.median(c_values), statistics.median(rust_values)
        result[metric] = {
            "pinned_c_median": c_median,
            "rust_engine_median": rust_median,
            "ratio_rust_over_c": rust_median / c_median if c_median > 0 else None,
        }
        if metric in MEMORY_BOUND_SEEDS:
            distribution = ratio_distribution(c_values, rust_values, seed=seed ^ MEMORY_BOUND_SEEDS[metric])
            result[metric]["ratio_bootstrap_95th_percentile"] = quantile(distribution, 0.95) if distribution else None
    result["bootstrap"] = {"resamples": BOOTSTRAP_RESAMPLES, "seed": seed}
    return result


def architecture_summary(manifest: Mapping[str, Any], rows: Mapping[str, Any]) -> dict[str, Any]:
    """Indicative values behind plan.md's early architecture sanity check."""

    names = manifest["architecture_rows"]
    single = rows.get(names["single_thread"], {})
    four = rows.get(names["four_thread"], {})
    if single.get("status") != "measured" or four.get("status") != "measured":
        return {"status": "not-measured", "rows": {key: names[key] for key in ("single_thread", "four_thread")}}
    single_cost = single["comparison"]["median_ns_per_op"]
    four_cost = four["comparison"]["median_ns_per_op"]
    single_cpu = single["comparison"]["median_cpu_ns_per_op"]
    four_cpu = four["comparison"]["median_cpu_ns_per_op"]
    return {
        "status": "measured",
        "rows": {key: names[key] for key in ("single_thread", "four_thread")},
        "single_thread_throughput_ratio_rust_over_c": single["comparison"]["throughput_ratio_rust_over_c"],
        "single_thread_cpu_throughput_ratio_rust_over_c": single["comparison"]["cpu_throughput_ratio_rust_over_c"],
        "four_thread_throughput_ratio_rust_over_c": four["comparison"]["throughput_ratio_rust_over_c"],
        # Four-worker aggregate wall throughput over the same lane's
        # one-worker throughput; independent owners approach 4 only on four
        # otherwise idle CPUs.
        "four_worker_wall_self_scaling": {lane: single_cost[lane] / four_cost[lane] for lane in LANES},
        # Per-call CPU cost with four workers over one worker. Independent
        # owners stay near 1 even on a loaded host; shared locks or contended
        # cache lines raise it.
        "four_worker_cpu_cost_growth": {lane: four_cpu[lane] / single_cpu[lane] for lane in LANES},
    }


def matrix_summary(rows: Mapping[str, Any]) -> dict[str, Any]:
    measured = {name: row for name, row in rows.items() if row.get("status") == "measured"}
    if not measured:
        return {"status": "not-measured"}
    ratios = {name: row["comparison"]["throughput_ratio_rust_over_c"]["median"] for name, row in measured.items()}
    return {
        "status": "measured",
        "measured_rows": len(measured),
        "throughput_ratio_rust_over_c_geometric_mean": math.exp(statistics.fmean(math.log(value) for value in ratios.values())),
        "slowest_rows": sorted(ratios, key=ratios.__getitem__)[:5],
    }


# ---- builds -----------------------------------------------------------------


def c_lane_commands(
    compiler: str, manifest: Mapping[str, Any], source: Path, build: Path
) -> tuple[list[list[str]], Path, Path]:
    """Compile the pinned sources, the backend, and the fixture separately."""

    fixture_flags = list(manifest["shared_build"]["fixture_flags"])
    source_flags = list(manifest["lanes"]["pinned_c"]["source_configuration_flags"])
    commands: list[list[str]] = []
    objects: list[Path] = []
    for item in shared.ORACLE_SOURCES:
        output = build / ("mimalloc-" + item.replace("/", "-").removesuffix(".c") + ".o")
        commands.append(
            [compiler, "-std=gnu11", *source_flags, "-fno-pie", "-ffunction-sections", "-fdata-sections",
             "-I", str(source / "include"), "-c", str(source / item), "-o", str(output)]
        )
        objects.append(output)
    backend = build / "engine-c-backend.o"
    commands.append(
        [compiler, *fixture_flags, "-I", str(FIXTURE_ROOT), "-I", str(source / "include"),
         "-c", str(C_BACKEND), "-o", str(backend)]
    )
    fixture = build / "engine-fixture-c.o"
    commands.append([compiler, *fixture_flags, "-I", str(FIXTURE_ROOT), "-c", str(FIXTURE), "-o", str(fixture)])
    binary = build / "engine-fixture-pinned-c"
    link_map = build / "engine-fixture-pinned-c.map"
    commands.append(
        [compiler, *manifest["shared_build"]["link_flags"], f"-Wl,-Map,{link_map}",
         str(fixture), str(backend), *(str(item) for item in objects), "-o", str(binary)]
    )
    return commands, binary, link_map


def rust_engine_cargo_command(manifest: Mapping[str, Any], target_directory: Path) -> tuple[list[str], dict[str, str]]:
    environment = dict(os.environ)
    # RUSTFLAGS replaces the checkout's `-C link-dead-code` build flag, which
    # affects only final links; the engine is linked by the rustc step below.
    environment["RUSTFLAGS"] = " ".join(manifest["lanes"]["rust_engine"]["engine_rustflags"])
    return (
        ["cargo", "build", "--locked", "--package", "crabc-mimalloc", "--lib", "--target", RUST_TARGET,
         "--release", "--target-dir", str(target_directory), "--message-format=json-render-diagnostics"],
        environment,
    )


def cargo_rlibs(cargo_stdout: str) -> dict[str, Path]:
    """Map each built library crate name to its exact rlib from Cargo's messages.

    Cargo's build-directory layout is not a stable interface; its JSON
    artifact messages name the files the rustc step must consume.
    """

    rlibs: dict[str, Path] = {}
    for line in cargo_stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        candidates = [Path(item) for item in message.get("filenames", []) if item.endswith(".rlib")]
        if not candidates:
            continue
        chosen = candidates[0]
        name = message["target"]["name"].replace("-", "_")
        if name in rlibs and rlibs[name] != chosen:
            raise HarnessError(f"Cargo built two distinct {name} rlibs")
        rlibs[name] = chosen
    if "crabc_mimalloc" not in rlibs:
        raise HarnessError("Cargo did not report the crabc_mimalloc rlib")
    return rlibs


def rust_backend_rustc_command(manifest: Mapping[str, Any], rlibs: Mapping[str, Path], output: Path) -> list[str]:
    search = sorted({str(path.parent) for path in rlibs.values()})
    return [
        "rustc", "--edition", "2024", "--target", RUST_TARGET, "--crate-type", "staticlib",
        "--crate-name", "crabc_allocator_engine_rust_backend", str(RUST_BACKEND),
        *(argument for directory in search for argument in ("-L", f"dependency={directory}")),
        "--extern", f"crabc_mimalloc={rlibs['crabc_mimalloc']}",
        *manifest["lanes"]["rust_engine"]["rustc_flags"],
        "--print=native-static-libs", "-o", str(output),
    ]


def parse_native_static_libraries(output: str) -> list[str]:
    matches = re.findall(r"(?m)^\s*(?:note:\s*)?native-static-libs:\s*(.*?)\s*$", output)
    if len(matches) != 1:
        raise HarnessError("Rust backend native-static-libs output is absent or ambiguous")
    return matches[0].split()


def run_build_commands(
    commands: Sequence[Sequence[str]], *, cwd: Path, description: str,
    environment: Mapping[str, str] | None = None, keep_stdout: bool = False,
) -> list[dict[str, Any]]:
    records = []
    for command in commands:
        completed = subprocess.run(list(command), cwd=cwd, env=None if environment is None else dict(environment),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        record = {"command": list(command), "status": completed.returncode,
                  "stdout": completed.stdout[-8192:], "stderr": completed.stderr[-8192:]}
        if environment is not None and "RUSTFLAGS" in environment:
            record["rustflags"] = environment["RUSTFLAGS"]
        if keep_stdout:
            record["full_stdout"] = completed.stdout
        records.append(record)
        require_success(record, description)
    return records


def audit_static_executable(readelf: str, binary: Path) -> dict[str, Any]:
    header = command_record((readelf, "-h", str(binary)), cwd=ROOT)
    require_success(header, "fixture ELF header inspection")
    shared.parse_elf_identity(str(header["stdout"]))
    headers = command_record((readelf, "-lW", str(binary)), cwd=ROOT)
    require_success(headers, "fixture program header inspection")
    if "INTERP" in str(headers["stdout"]) or "DYNAMIC" in str(headers["stdout"]):
        raise HarnessError(f"engine fixture is not a static executable: {binary.name}")
    elf_type = re.search(r"(?m)^\s*Type:\s*(\S+)", str(header["stdout"]))
    if elf_type is None or elf_type.group(1) != "EXEC":
        raise HarnessError(f"engine fixture is not a non-PIE executable: {binary.name}")
    return {"artifact": artifact_record(binary), "elf": dict(shared.EXPECTED_ELF), "type": "static-non-pie-exec"}


LINK_MAP_SECTION = re.compile(r"^ (\.text\S*|\.rodata\S*|\.data\S*|\.tdata\S*|\.tbss\S*|\.bss\S*)(?:\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S+))?\s*$")
LINK_MAP_CONTINUATION = re.compile(r"^\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S+)\s*$")


def link_map_attribution(link_map: Path, owner) -> dict[str, dict[str, int]]:
    """Sum kept input-section bytes by owner(input file) and output class."""

    totals: dict[str, dict[str, int]] = {}
    pending: str | None = None
    in_discarded = False
    for raw in link_map.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("Discarded input sections"):
            in_discarded = True
            continue
        if raw.startswith("Memory map") or raw.startswith("Linker script and memory map"):
            in_discarded = False
            continue
        if in_discarded:
            continue
        match = LINK_MAP_SECTION.match(raw)
        if match is not None:
            section, address, size, source = match.groups()
            if address is None:
                pending = section
                continue
            pending = None
        elif pending is not None and (continuation := LINK_MAP_CONTINUATION.match(raw)):
            section = pending
            address, size, source = continuation.groups()
            pending = None
        else:
            pending = None
            continue
        if int(address, 16) == 0:
            continue
        group = owner(source)
        kind = "text" if section.startswith(".text") else ("rodata" if section.startswith(".rodata") else "data")
        entry = totals.setdefault(group, {"text": 0, "rodata": 0, "data": 0})
        entry[kind] += int(size, 16)
    return totals


def c_lane_owner(source: str) -> str:
    name = Path(source.split("(")[0]).name
    if name.startswith("mimalloc-") or name == "engine-c-backend.o":
        return "allocator"
    if name == "engine-fixture-c.o":
        return "fixture"
    return "runtime"


def rust_lane_owner(source: str) -> str:
    name = Path(source.split("(")[0]).name
    if name.startswith("libcrabc_allocator_engine_rust_backend"):
        return "allocator"
    if name == "engine-fixture-rust.o":
        return "fixture"
    return "runtime"


def build_lanes(manifest: Mapping[str, Any], source: Path, build: Path, *, compiler: str, readelf: str) -> dict[str, Any]:
    build.mkdir(parents=True, exist_ok=True)
    c_commands, c_binary, c_map = c_lane_commands(compiler, manifest, source, build)
    c_records = run_build_commands(c_commands, cwd=source, description="pinned-C engine lane build")

    # Cargo's fingerprinted target directory is reusable state, not evidence;
    # the linked products below are retained per report.
    target_directory = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / ".work/allocator-x86_64/target")) / "perf-engine"
    cargo_command, cargo_environment = rust_engine_cargo_command(manifest, target_directory)
    cargo_records = run_build_commands(
        [cargo_command], cwd=ROOT, description="crabc-mimalloc release rlib build",
        environment=cargo_environment, keep_stdout=True,
    )
    rlibs = cargo_rlibs(cargo_records[0].pop("full_stdout"))
    static_library = build / "libcrabc_allocator_engine_rust_backend.a"
    rustc_command = rust_backend_rustc_command(manifest, rlibs, static_library)
    rustc_records = run_build_commands([rustc_command], cwd=ROOT, description="Rust engine backend staticlib build")
    native_libraries = parse_native_static_libraries(rustc_records[0]["stdout"] + "\n" + rustc_records[0]["stderr"])
    fixture_object = build / "engine-fixture-rust.o"
    fixture_command = [compiler, *manifest["shared_build"]["fixture_flags"], "-I", str(FIXTURE_ROOT), "-c", str(FIXTURE), "-o", str(fixture_object)]
    rust_binary = build / "engine-fixture-rust-engine"
    rust_map = build / "engine-fixture-rust-engine.map"
    link_command = [
        compiler, *manifest["shared_build"]["link_flags"], f"-Wl,-Map,{rust_map}",
        str(fixture_object), str(static_library), *native_libraries, "-o", str(rust_binary),
    ]
    rust_records = run_build_commands([fixture_command, link_command], cwd=ROOT, description="Rust engine lane fixture link")

    if sha256_file(build / "engine-fixture-c.o") != sha256_file(fixture_object):
        raise HarnessError("the shared fixture object differs between lanes; the workload is not source- and build-identical")
    return {
        "binaries": {"pinned_c": c_binary, "rust_engine": rust_binary},
        "records": {
            "pinned_c": {
                "build_commands": c_records,
                "executable": audit_static_executable(readelf, c_binary),
                "link_map": artifact_record(c_map),
                "size_attribution_bytes": link_map_attribution(c_map, c_lane_owner),
            },
            "rust_engine": {
                "cargo": cargo_records,
                "rustc": rustc_records,
                "native_static_libraries": native_libraries,
                "static_library": artifact_record(static_library),
                "fixture_link": rust_records,
                "executable": audit_static_executable(readelf, rust_binary),
                "link_map": artifact_record(rust_map),
                "size_attribution_bytes": link_map_attribution(rust_map, rust_lane_owner),
            },
            "shared_fixture_object_sha256": sha256_file(fixture_object),
        },
    }


def code_size_comparison(records: Mapping[str, Any]) -> dict[str, Any]:
    c_allocator = records["pinned_c"]["size_attribution_bytes"].get("allocator")
    rust_allocator = records["rust_engine"]["size_attribution_bytes"].get("allocator")
    if not c_allocator or not rust_allocator:
        raise HarnessError("link-map attribution found no allocator input sections")
    c_code = c_allocator["text"] + c_allocator["rodata"]
    rust_code = rust_allocator["text"] + rust_allocator["rodata"]
    return {
        "attribution": "kept input sections of the allocator objects (pinned-C sources plus backend; Rust backend staticlib including its engine, core, and compiler-builtins members) from each final link map",
        "pinned_c_text_rodata_bytes": c_code,
        "rust_engine_text_rodata_bytes": rust_code,
        "growth_rust_over_c": rust_code / c_code - 1.0,
    }


# ---- provenance -------------------------------------------------------------


def tree_digest(paths: Sequence[Path]) -> dict[str, Any]:
    """Identify the exact engine source tree a report measured."""

    digest = hashlib.sha256()
    count = 0
    for base in paths:
        for path in sorted(item for item in base.rglob("*") if item.is_file()):
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(b"\0")
            digest.update(sha256_file(path).encode())
            digest.update(b"\n")
            count += 1
    return {"files": count, "sha256": digest.hexdigest(), "roots": [path.relative_to(ROOT).as_posix() for path in paths]}


def git_provenance() -> dict[str, Any]:
    head = command_record(("git", "-C", str(ROOT), "rev-parse", "HEAD"), cwd=ROOT)
    status = command_record(("git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=normal"), cwd=ROOT)
    if head["status"] != 0 or status["status"] != 0:
        return {"status": "unavailable", "detail": (str(head["stderr"]) + str(status["stderr"]))[:512]}
    dirty = sorted(line for line in str(status["stdout"]).splitlines() if line.strip())
    return {"head": str(head["stdout"]).strip(), "clean": not dirty, "dirty_paths": dirty}


def host_provenance(cpus: Sequence[int]) -> dict[str, Any]:
    def read(path: str) -> str | None:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return None

    cpuinfo = read("/proc/cpuinfo") or ""
    model = re.search(r"(?m)^model name\s*:\s*(.+)$", cpuinfo)
    governors = {}
    for cpu in cpus:
        value = read(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
        if value is not None:
            governors[str(cpu)] = value
    return {
        "allowed_cpus": sorted(os.sched_getaffinity(0)),
        "cpu_model": model.group(1) if model else None,
        "kernel_release": platform.release(),
        "logical_cpus": os.cpu_count(),
        "measurement_cpus": list(cpus),
        "scaling_governors": governors,
        "transparent_hugepage": read("/sys/kernel/mm/transparent_hugepage/enabled"),
    }


def tool_versions() -> dict[str, str]:
    versions = {}
    for tool, argument in (("rustc", "-Vv"), ("cargo", "-V"), ("musl-gcc", "--version"), ("readelf", "--version")):
        record = command_record((tool, argument), cwd=ROOT)
        require_success(record, f"{tool} version probe")
        versions[tool] = str(record["stdout"]).strip()
    return versions


HARNESS_FILES = (ALLOCATOR_ROOT / "perf_engine_x86_64.py", ALLOCATOR_ROOT / "perf_x86_64.py")
ENGINE_MANIFESTS = (ROOT / "Cargo.toml", ROOT / "crabc-mimalloc/Cargo.toml", ROOT / "crabc-core/Cargo.toml")
ENGINE_SOURCE_ROOTS = (ROOT / "crabc-mimalloc/src", ROOT / "crabc-core/src")


def sealed_inputs() -> dict[str, Any]:
    """Every checkout input that determines what a report measured.

    A report's copy is its source seal: the qualified-report reader
    recomputes this from the reading checkout, so a later edit of the
    fixture, either backend, the manifest, this harness, the engine sources
    or their Cargo/toolchain pins invalidates the report.
    """

    return {
        "fixture": file_record(FIXTURE),
        "header": file_record(HEADER),
        "c_backend": file_record(C_BACKEND),
        "rust_backend": file_record(RUST_BACKEND),
        "manifest": file_record(MANIFEST),
        "harness": [file_record(path) for path in HARNESS_FILES],
        "cargo_lock": file_record(ROOT / "Cargo.lock"),
        "engine_manifests": [file_record(path) for path in ENGINE_MANIFESTS],
        "rust_toolchain": file_record(ROOT / "rust-toolchain.toml"),
        "engine_sources": tree_digest(list(ENGINE_SOURCE_ROOTS)),
    }


def input_provenance(archive: Path, pin: Mapping[str, str]) -> dict[str, Any]:
    return {
        **sealed_inputs(),
        "mimalloc": {"archive": file_record(archive), **{key: pin[key] for key in ("version", "tag", "revision")}},
    }


# ---- host contention --------------------------------------------------------
#
# A report is uncontended only when every contention window it records meets
# all of these limits. The limits are part of the report and reread by the
# qualified-report reader, which reclassifies the raw windows itself.
#
# * The 1-minute load average before any measurement is at most
#   UNCONTENDED_START_LOAD1_MAX. (Later load averages include this run's own
#   workers, so they are recorded but classified through the CPU windows.)
# * Over every window (one before measuring, one before each row while no
#   fixture runs, one after the last row) the whole host is at most
#   UNCONTENDED_HOST_BUSY_MAX busy and every measurement CPU at most
#   UNCONTENDED_CPU_BUSY_MAX busy, from /proc/stat (host-wide even inside the
#   container; steal time counts as busy).
# * No other process visible to the harness uses more than
#   UNCONTENDED_PROCESS_CPU_MAX of one CPU during a window.
# * Where cpufreq is exposed, every measurement CPU uses the `performance`
#   governor; a missing cpufreq interface is recorded, not disqualifying.
# * The container has no CFS quota and was never throttled during the run.
UNCONTENDED_START_LOAD1_MAX = 1.0
UNCONTENDED_HOST_BUSY_MAX = 0.05
UNCONTENDED_CPU_BUSY_MAX = 0.10
UNCONTENDED_PROCESS_CPU_MAX = 0.05
UNCONTENDED_GOVERNOR = "performance"
CONTENTION_EDGE_WINDOW_SECONDS = 1.0
CONTENTION_ROW_WINDOW_SECONDS = 0.5
UNCONTENDED_THRESHOLDS = {
    "start_load1_max": UNCONTENDED_START_LOAD1_MAX,
    "host_busy_max": UNCONTENDED_HOST_BUSY_MAX,
    "cpu_busy_max": UNCONTENDED_CPU_BUSY_MAX,
    "process_cpu_max": UNCONTENDED_PROCESS_CPU_MAX,
    "governor": UNCONTENDED_GOVERNOR,
    "edge_window_seconds": CONTENTION_EDGE_WINDOW_SECONDS,
    "row_window_seconds": CONTENTION_ROW_WINDOW_SECONDS,
}


def _read_text(path: Path | str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def proc_stat_record() -> dict[str, Any]:
    """Per-CPU jiffies and runnable/blocked counts from /proc/stat."""

    text = _read_text("/proc/stat")
    if text is None:
        raise HarnessError("cannot read /proc/stat")
    cpus: dict[str, list[int]] = {}
    counters: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu"):
            cpus[fields[0].removeprefix("cpu") or "all"] = [int(value) for value in fields[1:]]
        elif fields and fields[0] in {"procs_running", "procs_blocked", "ctxt"}:
            counters[fields[0]] = int(fields[1])
    return {"cpus": cpus, **counters}


def visible_process_ticks() -> dict[str, dict[str, Any]]:
    """utime+stime of every process in this PID namespace except the harness."""

    result: dict[str, dict[str, Any]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        text = _read_text(entry / "stat")
        if text is None or ")" not in text:
            continue
        comm = text[text.index("(") + 1:text.rindex(")")]
        fields = text[text.rindex(")") + 2:].split()
        result[entry.name] = {"comm": comm, "ticks": int(fields[11]) + int(fields[12])}
    return result


def cgroup_cpu_record() -> dict[str, Any]:
    stat = _read_text("/sys/fs/cgroup/cpu.stat")
    return {
        "cpu_max": (_read_text("/sys/fs/cgroup/cpu.max") or "").strip() or None,
        "cpu_stat": {line.split()[0]: int(line.split()[1]) for line in (stat or "").splitlines() if len(line.split()) == 2},
    }


def frequency_record(cpus: Sequence[int]) -> dict[str, Any]:
    base = Path("/sys/devices/system/cpu")
    per_cpu = {}
    for cpu in cpus:
        directory = base / f"cpu{cpu}/cpufreq"
        values = {}
        for name in ("scaling_driver", "scaling_governor", "scaling_cur_freq", "scaling_min_freq",
                     "scaling_max_freq", "cpuinfo_max_freq", "energy_performance_preference"):
            value = _read_text(directory / name)
            if value is not None:
                values[name] = value.strip()
        per_cpu[str(cpu)] = values
    boost = _read_text(base / "cpufreq/boost")
    return {"cpus": per_cpu, "boost": boost.strip() if boost is not None else None}


def contention_window(label: str, seconds: float) -> dict[str, Any]:
    """Raw host activity over one idle interval of the harness."""

    load_before = (_read_text("/proc/loadavg") or "").strip()
    stat_before = proc_stat_record()
    processes_before = visible_process_ticks()
    started = time.monotonic_ns()
    time.sleep(seconds)
    elapsed = time.monotonic_ns() - started
    stat_after = proc_stat_record()
    processes_after = visible_process_ticks()
    load_after = (_read_text("/proc/loadavg") or "").strip()
    active = {}
    for pid, after in processes_after.items():
        before = processes_before.get(pid, {"ticks": 0})
        if after["ticks"] != before["ticks"]:
            active[pid] = {"comm": after["comm"], "ticks_before": before["ticks"], "ticks_after": after["ticks"]}
    return {
        "label": label,
        "elapsed_ns": elapsed,
        "loadavg": [load_before, load_after],
        "stat_before": stat_before,
        "stat_after": stat_after,
        "visible_processes": len(processes_after),
        "active_processes": active,
    }


def host_record_start(cpus: Sequence[int]) -> dict[str, Any]:
    return {
        "thresholds": dict(UNCONTENDED_THRESHOLDS),
        "measurement_cpus": list(cpus),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "frequency_start": frequency_record(cpus),
        "cgroup_start": cgroup_cpu_record(),
        "windows": [contention_window("start", CONTENTION_EDGE_WINDOW_SECONDS)],
    }


def host_record_finish(evidence: dict[str, Any]) -> dict[str, Any]:
    evidence["windows"].append(contention_window("end", CONTENTION_EDGE_WINDOW_SECONDS))
    evidence["frequency_end"] = frequency_record(evidence["measurement_cpus"])
    evidence["cgroup_end"] = cgroup_cpu_record()
    return evidence


def _busy_fraction(before: Sequence[int], after: Sequence[int]) -> float | None:
    # user nice system idle iowait irq softirq steal (guest time is in user)
    delta = [late - early for early, late in zip(before[:8], after[:8])]
    total = sum(delta)
    if total <= 0:
        return None
    return (total - delta[3] - delta[4]) / total


def classify_host(evidence: Mapping[str, Any]) -> list[str]:
    """Every reason the recorded raw host evidence is not uncontended."""

    reasons: list[str] = []
    try:
        thresholds = evidence["thresholds"]
        windows = evidence["windows"]
        cpus = [str(cpu) for cpu in evidence["measurement_cpus"]]
        ticks_per_second = evidence["clock_ticks_per_second"]
    except (KeyError, TypeError):
        return ["host evidence lacks its thresholds, windows, measurement CPUs or clock rate"]
    if thresholds != UNCONTENDED_THRESHOLDS:
        reasons.append(f"host evidence was classified under other thresholds: {thresholds}")
    if not isinstance(windows, list) or len(windows) < 2 or windows[0].get("label") != "start" or windows[-1].get("label") != "end":
        return reasons + ["host evidence lacks its start and end contention windows"]
    try:
        load1 = float(windows[0]["loadavg"][0].split()[0])
    except (IndexError, ValueError, AttributeError):
        load1 = math.inf
    if load1 > UNCONTENDED_START_LOAD1_MAX:
        reasons.append(f"start 1-minute load average {load1} > {UNCONTENDED_START_LOAD1_MAX}")
    for window in windows:
        label = window.get("label")
        before, after = window["stat_before"]["cpus"], window["stat_after"]["cpus"]
        host = _busy_fraction(before.get("all", []), after.get("all", []))
        if host is None or host > UNCONTENDED_HOST_BUSY_MAX:
            reasons.append(f"window {label}: host busy fraction {host} > {UNCONTENDED_HOST_BUSY_MAX}")
        for cpu in cpus:
            busy = _busy_fraction(before.get(cpu, []), after.get(cpu, []))
            if busy is None or busy > UNCONTENDED_CPU_BUSY_MAX:
                reasons.append(f"window {label}: measurement CPU {cpu} busy fraction {busy} > {UNCONTENDED_CPU_BUSY_MAX}")
        seconds = window["elapsed_ns"] / 1e9
        for pid, process in sorted(window["active_processes"].items()):
            share = (process["ticks_after"] - process["ticks_before"]) / ticks_per_second / seconds
            if share > UNCONTENDED_PROCESS_CPU_MAX:
                reasons.append(f"window {label}: process {pid} ({process['comm']}) used {share:.3f} CPU")
    for key in ("frequency_start", "frequency_end"):
        for cpu, values in sorted(evidence[key]["cpus"].items()):
            governor = values.get("scaling_governor")
            if governor is not None and governor != UNCONTENDED_GOVERNOR:
                reasons.append(f"{key}: CPU {cpu} governor {governor} is not {UNCONTENDED_GOVERNOR}")
    quota = evidence["cgroup_start"]["cpu_max"]
    if quota is not None and not quota.startswith("max"):
        reasons.append(f"container CPU quota {quota!r} is set")
    throttled = [evidence[key]["cpu_stat"].get("nr_throttled", 0) for key in ("cgroup_start", "cgroup_end")]
    if throttled[1] != throttled[0]:
        reasons.append(f"container was CPU-throttled {throttled[1] - throttled[0]} time(s) during the run")
    return reasons


def uncontended_host_record(evidence: Mapping[str, Any]) -> dict[str, Any]:
    reasons = classify_host(evidence)
    return {"status": "contended" if reasons else "uncontended", "reasons": reasons, "evidence": dict(evidence)}


# ---- qualified full reports -------------------------------------------------
#
# plan.md's M9 row and its "Allocator verification and performance" table
# need qualified full reports: the complete matrix in full mode on an
# uncontended host, sealed to the reading checkout's sources. The reader
# below never trusts a report's own summaries or classification: it
# recomputes every comparison and bound from the raw samples, reclassifies
# the raw host evidence, and recomputes the source seal.

QUALIFIED_MODE = "full"
QUALIFIED_ROW_SET = "matrix"
QUALIFIED_HOST_FIELDS = (
    "cpu_model", "kernel_release", "logical_cpus", "allowed_cpus", "measurement_cpus",
    "scaling_governors", "transparent_hugepage",
)
# Linux keeps no PSS high-water mark, so a timed row's peak PSS is read at
# the fixture's untimed READY_PEAK pause; a report without it cannot qualify.
PEAK_HOOK_GAP = "report was measured with --no-peak-hook, so timed rows have no peak-state PSS"


def metric_coverage(report: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, list[str]]:
    """Per matrix row, the promotion-table metrics its raw samples lack."""

    timed, memory = selected_rows(manifest, QUALIFIED_ROW_SET)
    missing: dict[str, list[str]] = {}
    for row in timed:
        entry = report.get("rows", {}).get(row["name"])
        if not isinstance(entry, Mapping) or entry.get("status") != "measured":
            missing[row["name"]] = ["throughput", "tail_latency", "peak_rss", "peak_pss"]
            continue
        lacks = []
        for sample in (*entry["lanes"]["pinned_c"]["samples"], *entry["lanes"]["rust_engine"]["samples"]):
            if not isinstance(sample, Mapping):
                continue
            if not isinstance(sample.get("process", {}).get("exit_memory"), Mapping) and "peak_rss" not in lacks:
                lacks.append("peak_rss")
            if sample_peak_pss_kib(sample) is None and "peak_pss" not in lacks:
                lacks.append("peak_pss")
        if lacks:
            missing[row["name"]] = lacks
    for row in memory:
        entry = report.get("memory_rows", {}).get(row["name"])
        if not isinstance(entry, Mapping) or entry.get("status") != "measured":
            missing[row["name"]] = ["peak_rss", "peak_pss"]
    return missing


def critical_rows(manifest: Mapping[str, Any]) -> list[str]:
    return sorted(manifest["critical_rows"]["rows"])


def geometric_mean_distribution(distributions: Sequence[Sequence[float]]) -> list[float]:
    """Suite geometric mean per bootstrap resample of independently resampled rows."""

    return [math.exp(statistics.fmean(math.log(values[index]) for values in distributions))
            for index in range(len(distributions[0]))]


def _lane_samples(entry: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    return list(entry["lanes"]["pinned_c"]["samples"]), list(entry["lanes"]["rust_engine"]["samples"])


def source_seal_unmet(inputs: Mapping[str, Any]) -> list[str]:
    """Differences between a recorded source seal and this checkout."""

    unmet = []
    current = sealed_inputs()
    for key, value in current.items():
        if inputs.get(key) != value:
            unmet.append(f"source seal: {key} differs from this checkout")
    pin = shared.load_pin()
    mimalloc = inputs.get("mimalloc", {})
    if {key: mimalloc.get(key) for key in ("version", "tag", "revision")} != {
        key: pin[key] for key in ("version", "tag", "revision")
    } or mimalloc.get("archive", {}).get("sha256") != pin["sha256"]:
        unmet.append("source seal: pinned mimalloc identity or archive digest differs from compat/upstreams.toml")
    return unmet


def _row_unmet(group: str, row: Mapping[str, Any], entry: Any, mode: Mapping[str, Any]) -> list[str]:
    name = row["name"]
    if not isinstance(entry, Mapping) or entry.get("status") != "measured":
        status = entry.get("status") if isinstance(entry, Mapping) else None
        reason = entry.get("reason") if isinstance(entry, Mapping) else None
        return [f"{group} row {name} is {status or 'absent'}" + (f": {reason}" if reason else "")]
    unmet = []
    if entry.get("workload") != row["workload"] or entry.get("params") != row["params"]:
        unmet.append(f"{group} row {name} does not measure the manifest's workload and parameters")
    c_samples, rust_samples = _lane_samples(entry)
    if len(c_samples) != mode["samples"] or len(rust_samples) != mode["samples"] or None in (*c_samples, *rust_samples):
        unmet.append(f"{group} row {name} lacks the full mode's {mode['samples']} samples per lane")
        return unmet
    if group == "timed":
        batches = expected_batches(row, mode["batch_divisor"])
        if any(len(sample["batches"]) != batches for sample in (*c_samples, *rust_samples)):
            unmet.append(f"timed row {name} lacks {batches} batches per sample")
            return unmet
        recomputed = throughput_comparison(c_samples, rust_samples, seed=entry["seed"])
    else:
        recomputed = memory_comparison(c_samples, rust_samples, seed=entry["seed"])
    if recomputed != entry.get("comparison"):
        unmet.append(f"{group} row {name} comparison differs from a recomputation of its raw samples")
    return unmet


def qualification_unmet(report: Mapping[str, Any], manifest: Mapping[str, Any] | None = None) -> list[str]:
    """Every reason one engine report is not a qualified full report."""

    manifest = load_manifest() if manifest is None else manifest
    unmet: list[str] = []
    if report.get("schema") != SCHEMA or report.get("kind") != KIND:
        return [f"report is not a schema-{SCHEMA} {KIND} report"]
    if report.get("mode") != QUALIFIED_MODE or report.get("row_set") != QUALIFIED_ROW_SET:
        unmet.append(f"report is --{report.get('mode')} --set {report.get('row_set')}, "
                     f"not --{QUALIFIED_MODE} --set {QUALIFIED_ROW_SET}")
    if report.get("status") != "ok" or report.get("failed_rows"):
        unmet.append(f"report status is {report.get('status')} with failed rows {report.get('failed_rows')}")
    if report.get("native_execution_provenance", {}).get("execution_mode") != "native":
        unmet.append("report lacks native x86-64 execution provenance")
    provenance = report.get("provenance", {})
    git = provenance.get("git", {})
    if git.get("clean") is not True:
        unmet.append(f"measured checkout was not a clean Git tree: {git.get('dirty_paths', git.get('status'))}")
    unmet.extend(source_seal_unmet(provenance.get("inputs", {})))
    host = provenance.get("host", {})
    missing_host = [field for field in QUALIFIED_HOST_FIELDS if field not in host]
    if missing_host:
        unmet.append(f"host identity lacks {missing_host}")
    mode = manifest["modes"][QUALIFIED_MODE]
    timed, memory = selected_rows(manifest, QUALIFIED_ROW_SET)
    if report.get("mode") == QUALIFIED_MODE:
        # Another mode's rows cannot meet the full schedule; its mode is the one reason.
        for group, rows, recorded in (("timed", timed, report.get("rows", {})),
                                      ("memory", memory, report.get("memory_rows", {}))):
            for row in rows:
                unmet.extend(_row_unmet(group, row, recorded.get(row["name"]), mode))
    if report.get("peak_hook") is not True:
        unmet.append(PEAK_HOOK_GAP)
    else:
        for name, lacks in sorted(metric_coverage(report, manifest).items()):
            if report.get("rows", {}).get(name, {}).get("status") == "measured":
                unmet.append(f"timed row {name} samples lack {', '.join(lacks)}")
    record = report.get("uncontended_host")
    if not isinstance(record, Mapping) or not isinstance(record.get("evidence"), Mapping):
        unmet.append("report has no uncontended_host record with raw evidence")
    else:
        reasons = classify_host(record["evidence"])
        status = "contended" if reasons else "uncontended"
        if record.get("status") != status or record.get("reasons") != reasons:
            unmet.append("uncontended_host classification differs from a reclassification of its raw evidence")
        unmet.extend(f"host is not uncontended: {reason}" for reason in reasons)
    return unmet


def qualified_metrics(report: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    """The promotion-table metrics, recomputed from every row's raw samples.

    Throughput bounds are one-sided 95% bootstrap bounds of the Rust/C
    median ratio (lower); p99 and memory bounds are upper. Suite geometric
    means resample every row independently per bootstrap draw. Any row
    without a bound leaves the geometric mean unset.
    """

    timed, memory = selected_rows(manifest, QUALIFIED_ROW_SET)
    throughput: dict[str, list[float]] = {}
    rss: dict[str, list[float] | None] = {}
    pss: dict[str, list[float] | None] = {}
    tail: dict[str, float | None] = {}
    for row in timed:
        entry = report["rows"][row["name"]]
        c_samples, rust_samples = _lane_samples(entry)
        seed = entry["seed"]
        throughput[row["name"]] = throughput_distribution(c_samples, rust_samples, seed=seed)
        rss[row["name"]] = ratio_distribution([sample_peak_rss_kib(item) for item in c_samples],
                                              [sample_peak_rss_kib(item) for item in rust_samples], seed=seed ^ RSS_SEED)
        pss[row["name"]] = ratio_distribution(peak_pss_values(c_samples) or [], peak_pss_values(rust_samples) or [],
                                              seed=seed ^ PSS_SEED)
        tail[row["name"]] = entry["comparison"]["batch_p99_ns_per_op"]["ratio_rust_over_c"]["bootstrap_95th_percentile"]
    for row in memory:
        entry = report["memory_rows"][row["name"]]
        c_samples, rust_samples = _lane_samples(entry)
        for target, metric in ((rss, "peak_rss_kib"), (pss, "live_pss_kib")):
            target[row["name"]] = ratio_distribution(memory_values(c_samples, metric), memory_values(rust_samples, metric),
                                                     seed=entry["seed"] ^ MEMORY_BOUND_SEEDS[metric])

    def upper(distribution: Sequence[float] | None) -> float | None:
        return quantile(distribution, 0.95) if distribution else None

    def geomean_upper(distributions: Mapping[str, Sequence[float] | None]) -> float | None:
        values = list(distributions.values())
        return quantile(geometric_mean_distribution(values), 0.95) if values and all(values) else None

    roster = critical_rows(manifest)
    return {
        "throughput": {
            "suite_geometric_mean_lower_95": quantile(geometric_mean_distribution(list(throughput.values())), 0.05),
            "critical_lower_95": {name: quantile(throughput[name], 0.05) for name in roster},
        },
        "tail_latency": {"critical_p99_upper_95": {name: tail[name] for name in roster}},
        "memory": {
            "geometric_mean_peak_upper": {"rss": geomean_upper(rss), "pss": geomean_upper(pss)},
            "critical_peak_upper": {name: {"rss": upper(rss[name]), "pss": upper(pss[name])} for name in roster},
        },
    }


def report_identity(report: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Source, configuration and host identity; three qualified reports must share it."""

    provenance = report["provenance"]
    return {
        "source": dict(provenance["inputs"], mimalloc={
            key: provenance["inputs"]["mimalloc"].get(key) for key in ("version", "tag", "revision")
        } | {"archive_sha256": provenance["inputs"]["mimalloc"]["archive"]["sha256"]}),
        "configuration": {
            "schema": report["schema"], "kind": report["kind"], "mode": report["mode"], "row_set": report["row_set"],
            "critical_rows": critical_rows(manifest), "tools": provenance["tools"],
            "uncontended_thresholds": report.get("uncontended_host", {}).get("evidence", {}).get("thresholds"),
        },
        "host": {field: provenance["host"].get(field) for field in QUALIFIED_HOST_FIELDS},
    }


def _checked_report_path(root: Path, path: Path) -> Path:
    if Path(root).resolve() != ROOT.resolve():
        raise HarnessError(f"engine reports must be read by the checkout that owns this reader: {root}")
    path = Path(path)
    if not path.is_file():
        raise HarnessError(f"engine report is missing: {path}")
    return path


def inspect_full_report(root: Path, path: Path) -> dict[str, Any]:
    """Every unmet qualification condition of one report, plus its identity and metrics."""

    path = _checked_report_path(root, path)
    manifest = load_manifest()
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"unmet": [f"report is unreadable JSON: {error}"], "identity": None, "metrics": None}
    if not isinstance(report, dict):
        return {"unmet": ["report is not a JSON object"], "identity": None, "metrics": None}
    try:
        unmet = qualification_unmet(report, manifest)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        return {"unmet": [f"report is malformed: {type(error).__name__}: {error}"], "identity": None, "metrics": None}
    identity = metrics = None
    try:
        identity = report_identity(report, manifest)
        metrics = qualified_metrics(report, manifest)
    except (HarnessError, KeyError, TypeError, ValueError, AttributeError, IndexError, statistics.StatisticsError):
        # The unmet conditions above already name the incomplete rows.
        if not unmet:
            unmet.append("report metrics cannot be derived from its raw samples")
    try:
        coverage = metric_coverage(report, manifest)
    except (KeyError, TypeError, AttributeError):
        coverage = None
    return {"unmet": unmet, "identity": identity, "metrics": metrics, "critical_rows": critical_rows(manifest),
            "coverage": coverage}


def validate_qualified_full_report(root: Path, path: Path) -> dict[str, Any]:
    """Return ``{"identity", "metrics", "critical_rows"}`` of one qualified full report.

    Raises HarnessError naming every unmet condition otherwise. The
    ``performance.release`` gate applies the promotion thresholds to the
    returned metrics; this reader decides only whether the report is a
    qualified full measurement.
    """

    inspected = inspect_full_report(root, path)
    if inspected["unmet"]:
        raise HarnessError(f"{path} is not a qualified full report: " + "; ".join(inspected["unmet"]))
    return {key: inspected[key] for key in ("identity", "metrics", "critical_rows")}


# ---- peak-hook A/B -----------------------------------------------------------

PEAK_HOOK_AB_KIND = "crabc-mimalloc-x86_64-engine-peak-hook-ab"
PEAK_HOOK_VARIANTS = ("hook", "no_hook")


def peak_hook_plan(samples: int, *, seed: int) -> list[tuple[str, int]]:
    """Adjacent hook/no-hook process pairs in a recorded random order."""

    return [(PEAK_HOOK_VARIANTS[LANES.index(lane)], index) for lane, index in paired_plan(samples, seed=seed)]


def peak_hook_comparison(hook: Sequence[Mapping[str, Any]], no_hook: Sequence[Mapping[str, Any]], *, seed: int) -> dict[str, Any]:
    """Paired hook/no-hook ratios of per-call cost and slow-batch p99 cost."""

    result: dict[str, Any] = {"bootstrap": {"resamples": BOOTSTRAP_RESAMPLES, "seed": seed}}
    for offset, (metric, measure) in enumerate((("cost", sample_ns_per_op), ("batch_p99", sample_batch_p99_ns_per_op))):
        with_values = [measure(sample) for sample in hook]
        without_values = [measure(sample) for sample in no_hook]
        draws = paired_bootstrap(without_values, with_values, seed=seed + offset)
        result[metric] = {
            "unit": "wall ns per allocator call",
            "hook_samples": with_values,
            "no_hook_samples": without_values,
            "ratio_hook_over_no_hook": {
                "median": statistics.median(with_values) / statistics.median(without_values),
                "bootstrap_5th_percentile": quantile(draws, 0.05),
                "bootstrap_95th_percentile": quantile(draws, 0.95),
            },
        }
    return result


def peak_hook_summary(rows: Mapping[str, Any]) -> dict[str, Any]:
    outside: dict[str, dict[str, list[str]]] = {lane: {"cost": [], "batch_p99": []} for lane in LANES}
    ratios: dict[str, dict[str, list[float]]] = {lane: {"cost": [], "batch_p99": []} for lane in LANES}
    for name, row in sorted(rows.items()):
        for lane in LANES:
            comparison = row.get("lanes", {}).get(lane, {}).get("comparison")
            if comparison is None:
                continue
            for metric in ("cost", "batch_p99"):
                bound = comparison[metric]["ratio_hook_over_no_hook"]
                ratios[lane][metric].append(bound["median"])
                if not bound["bootstrap_5th_percentile"] <= 1.0 <= bound["bootstrap_95th_percentile"]:
                    outside[lane][metric].append(name)
    return {
        "rows_whose_90_percent_interval_excludes_1": outside,
        "median_ratio_geometric_mean": {
            lane: {metric: math.exp(statistics.fmean(math.log(value) for value in values)) if values else None
                   for metric, values in metrics.items()}
            for lane, metrics in ratios.items()
        },
    }


def measure_peak_hook_ab(
    rows: Sequence[Mapping[str, Any]], binaries: Mapping[str, Path], *, mode: Mapping[str, Any],
    cpu_pool: Sequence[int] | None, timeout: float, scratch: Path, seed: int,
) -> dict[str, Any]:
    """Each lane's timed samples with and without the READY_PEAK pause, interleaved in adjacent pairs."""

    results: dict[str, Any] = {}
    for row_index, row in enumerate(rows):
        needed = row_thread_count(row)
        cpus = choose_cpus(cpu_pool, needed)
        entry: dict[str, Any] = {"workload": row["workload"], "params": row["params"], "cpus": cpus, "lanes": {}}
        if not cpus:
            entry.update(status="unavailable", reason=f"needs {needed} distinct allowed CPUs")
            results[row["name"]] = entry
            continue
        entry["status"] = "measured"
        for lane_index, lane in enumerate(LANES):
            lane_seed = seed + 1009 * row_index + 17 * lane_index
            plan = peak_hook_plan(mode["samples"], seed=lane_seed)
            by_variant: dict[str, list[Any]] = {variant: [None] * mode["samples"] for variant in PEAK_HOOK_VARIANTS}
            kwargs = {"batch_divisor": mode["batch_divisor"], "cpus": cpus, "timeout": timeout, "scratch": scratch}
            try:
                for variant in PEAK_HOOK_VARIANTS:
                    for warmup in range(mode["warmup_processes"]):
                        run_timed_sample(binaries[lane], row, sample_name=f"ab-{row['name']}-{lane}-{variant}-w{warmup}",
                                         peak_hook=variant == "hook", **kwargs)
                for variant, index in plan:
                    by_variant[variant][index] = run_timed_sample(
                        binaries[lane], row, sample_name=f"ab-{row['name']}-{lane}-{variant}-{index}",
                        peak_hook=variant == "hook", **kwargs)
            except HarnessError as error:
                entry["lanes"][lane] = {"status": "failed", "reason": str(error)}
                entry["status"] = "failed"
                print(f"FAILED {row['name']} ({lane}): {error}", file=sys.stderr, flush=True)
                continue
            entry["lanes"][lane] = {
                "status": "measured",
                "sample_plan": [{"variant": variant, "sample_index": index} for variant, index in plan],
                "samples": by_variant,
                "comparison": peak_hook_comparison(by_variant["hook"], by_variant["no_hook"], seed=lane_seed),
            }
        results[row["name"]] = entry
        print(f"peak-hook A/B {row['name']}", file=sys.stderr, flush=True)
    return results


# ---- driver -----------------------------------------------------------------


def choose_cpus(requested: Sequence[int] | None, needed: int) -> list[int]:
    allowed = sorted(os.sched_getaffinity(0))
    if requested:
        if not set(requested) <= set(allowed) or len(set(requested)) != len(requested):
            raise HarnessError(f"requested CPUs {list(requested)} are not distinct allowed CPUs {allowed}")
        pool = list(requested)
    else:
        pool = allowed
    return pool[:needed] if len(pool) >= needed else []


def paired_plan(samples: int, *, seed: int) -> list[tuple[str, int]]:
    source = random.Random(seed)
    order = list(range(samples))
    source.shuffle(order)
    plan: list[tuple[str, int]] = []
    for index in order:
        first = LANES[source.getrandbits(1)]
        second = LANES[1] if first == LANES[0] else LANES[0]
        plan.extend(((first, index), (second, index)))
    return plan


def measure_rows(
    rows: Sequence[Mapping[str, Any]], binaries: Mapping[str, Path], *, memory: bool, mode: Mapping[str, Any],
    cpu_pool: Sequence[int] | None, timeout: float, scratch: Path, seed: int,
    host_evidence: dict[str, Any] | None = None, peak_hook: bool = True,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for row_index, row in enumerate(rows):
        if host_evidence is not None:
            host_evidence["windows"].append(contention_window(f"row:{row['name']}", CONTENTION_ROW_WINDOW_SECONDS))
        needed = row_thread_count(row)
        cpus = choose_cpus(cpu_pool, needed)
        entry: dict[str, Any] = {"workload": row["workload"], "params": row["params"], "measures": row.get("measures")}
        if not cpus:
            entry.update(status="unavailable", reason=f"needs {needed} distinct allowed CPUs")
            results[row["name"]] = entry
            continue
        row_seed = seed + 1009 * row_index
        runner = run_memory_sample if memory else run_timed_sample
        kwargs: dict[str, Any] = {"batch_divisor": mode["batch_divisor"], "cpus": cpus, "timeout": timeout, "scratch": scratch}
        if not memory:
            kwargs["peak_hook"] = peak_hook
        by_lane: dict[str, list[Any]] = {lane: [None] * mode["samples"] for lane in LANES}
        plan = paired_plan(mode["samples"], seed=row_seed)
        entry["cpus"] = cpus
        entry["seed"] = row_seed
        lane = LANES[0]
        try:
            for lane in LANES:
                for warmup in range(mode["warmup_processes"]):
                    runner(binaries[lane], row, sample_name=f"{row['name']}-{lane}-warmup-{warmup}", **kwargs)
            for lane, index in plan:
                sample = runner(binaries[lane], row, sample_name=f"{row['name']}-{lane}-{index}", **kwargs)
                sample["sample_index"] = index
                by_lane[lane][index] = sample
        except HarnessError as error:
            # Keep the raw failure and measure the remaining rows; the run
            # still exits nonzero (see `run`).
            entry.update(status="failed", failed_lane=lane, reason=str(error))
            results[row["name"]] = entry
            print(f"FAILED {row['name']} ({lane}): {error}", file=sys.stderr, flush=True)
            continue
        entry["sample_plan"] = [{"lane": lane, "sample_index": index} for lane, index in plan]
        entry["lanes"] = {lane: {"samples": by_lane[lane], "resources": resource_summary(by_lane[lane])} for lane in LANES}
        entry["comparison"] = (
            memory_comparison(by_lane["pinned_c"], by_lane["rust_engine"], seed=row_seed)
            if memory else throughput_comparison(by_lane["pinned_c"], by_lane["rust_engine"], seed=row_seed)
        )
        entry["status"] = "measured"
        results[row["name"]] = entry
        print(f"measured {row['name']}", file=sys.stderr, flush=True)
    return results


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--smoke", action="store_true", help="few samples, reduced batches (default)")
    mode.add_argument("--full", action="store_true", help="the manifest's larger sample schedule (still a development measurement)")
    parser.add_argument("--set", choices=ROW_SETS, default="architecture", dest="row_set")
    parser.add_argument("--cpus", default=None, help="comma-separated allowed CPUs to use, in order")
    parser.add_argument("--label", default="engine", help="report label")
    parser.add_argument("--offline", action="store_true", help="require the pinned C archive in the local cache")
    parser.add_argument("--timeout", type=float, default=180.0, help="per-process timeout in seconds")
    parser.add_argument("--no-peak-hook", dest="peak_hook", action="store_false",
                        help="omit the untimed READY_PEAK pause (only to show it leaves timed samples unchanged)")
    parser.add_argument("--peak-hook-ab", action="store_true",
                        help="instead of C versus Rust, measure each lane's timed rows with and without the "
                             "READY_PEAK pause in adjacent pairs")
    arguments = parser.parse_args(argv)
    validate_label(arguments.label)
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")
    if arguments.cpus is not None:
        try:
            arguments.cpus = [int(item) for item in arguments.cpus.split(",") if item]
        except ValueError:
            parser.error("--cpus must be comma-separated integers")
    return arguments


def run(arguments: argparse.Namespace) -> Path:
    provenance_native = shared.require_native_x86_64()
    manifest = load_manifest()
    mode_name = "full" if arguments.full else "smoke"
    mode = manifest["modes"][mode_name]
    timed_rows, memory_rows = selected_rows(manifest, arguments.row_set)
    widest = max(row_thread_count(row) for row in (*timed_rows, *memory_rows))
    measurement_cpus = choose_cpus(arguments.cpus, widest) or choose_cpus(arguments.cpus, 1)
    compiler = require_tool("musl-gcc")
    readelf = require_tool("readelf")
    pin = shared.load_pin()
    archive = shared.fetch_archive(pin, offline=arguments.offline)
    label = validate_label(arguments.label)
    base = REPORT_ROOT / "peak-hook-ab" if arguments.peak_hook_ab else REPORT_ROOT
    report_path = base / f"{label}.json"
    artifacts = base / f"{label}.artifacts"
    if artifacts.exists():
        shutil.rmtree(artifacts)
    artifacts.mkdir(parents=True)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": PEAK_HOOK_AB_KIND if arguments.peak_hook_ab else KIND,
        "label": label,
        "mode": mode_name,
        "row_set": arguments.row_set,
        "peak_hook": arguments.peak_hook,
        "status": "pending",
        "scope": {
            "claim": "pinned-C versus Rust persistent-engine performance and memory through one opaque engine boundary",
            "qualifying": "decided by validate_qualified_full_report, never by this field",
            "gate_verdicts": False,
            "fully_integrated_products": False,
        },
        "native_execution_provenance": provenance_native,
    }
    with tempfile.TemporaryDirectory(prefix="crabc-engine-perf-") as temporary:
        temporary_path = Path(temporary)
        source = shared.safe_extract(archive, temporary_path / "source", pin["archive_root"])
        report["provenance"] = {
            "git": git_provenance(),
            "host": host_provenance(measurement_cpus),
            "tools": tool_versions(),
            "inputs": input_provenance(archive, pin),
        }
        built = build_lanes(manifest, source, artifacts, compiler=compiler, readelf=readelf)
        report["lanes"] = built["records"]
        report["code_size"] = code_size_comparison(built["records"])
        scratch = temporary_path / "output"
        scratch.mkdir()
        load_before = list(os.getloadavg())
        host_evidence = host_record_start(measurement_cpus)
        seed = 0x4352_4142_4550
        if arguments.peak_hook_ab:
            report["rows"] = measure_peak_hook_ab(timed_rows, built["binaries"], mode=mode, cpu_pool=arguments.cpus,
                                                  timeout=arguments.timeout, scratch=scratch, seed=seed)
            report["host_load_average"] = {"before": load_before, "after": list(os.getloadavg())}
            report["uncontended_host"] = uncontended_host_record(host_record_finish(host_evidence))
            report["summary"] = peak_hook_summary(report["rows"])
            failed = sorted(name for name, row in report["rows"].items() if row["status"] == "failed")
            report["failed_rows"] = failed
            report["status"] = "failed-rows" if failed else "ok"
            atomic_write_json(report_path, report)
            return report_path
        report["rows"] = measure_rows(timed_rows, built["binaries"], memory=False, mode=mode,
                                      cpu_pool=arguments.cpus, timeout=arguments.timeout, scratch=scratch, seed=seed,
                                      host_evidence=host_evidence, peak_hook=arguments.peak_hook)
        report["memory_rows"] = measure_rows(memory_rows, built["binaries"], memory=True, mode=mode,
                                             cpu_pool=arguments.cpus, timeout=arguments.timeout, scratch=scratch,
                                             seed=seed ^ 0x4D45_4D, host_evidence=host_evidence)
        report["host_load_average"] = {"before": load_before, "after": list(os.getloadavg())}
        report["uncontended_host"] = uncontended_host_record(host_record_finish(host_evidence))
    report["architecture"] = architecture_summary(manifest, report["rows"])
    report["matrix"] = matrix_summary(report["rows"])
    failed = sorted(
        name for group in ("rows", "memory_rows") for name, row in report[group].items() if row["status"] == "failed"
    )
    report["failed_rows"] = failed
    report["status"] = "failed-rows" if failed else "ok"
    qualification = qualification_unmet(report)
    report["qualification"] = {"status": "non-qualifying" if qualification else "candidate", "unmet": qualification}
    atomic_write_json(report_path, report)
    if failed:
        raise HarnessError(f"rows failed: {', '.join(failed)}; raw failures are recorded in {report_path}")
    return report_path


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        path = run(arguments)
    except (HarnessError, OSError, tarfile.TarError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
