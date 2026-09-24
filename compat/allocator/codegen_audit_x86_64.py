#!/usr/bin/env python3
"""Native x86-64 optimized allocator codegen audit.

Builds the same two static engine-fixture executables as
``perf_engine_x86_64.py`` (pinned mimalloc v3.5.0 C and the Rust persistent
engine behind one opaque boundary), then inspects the active-target machine
code two ways:

* **Executed hot paths.** Each ``trace_*`` fixture scenario warms one
  operation to its steady state and brackets a single call with ``int3``
  markers. This runner ptrace-single-steps exactly that call and records the
  instruction sequence it retires: per-function instruction counts, call
  transitions (non-inlined helpers), atomic read-modify-writes and fences,
  divisions, thread-pointer (``%fs``) accesses, string operations, and any
  syscall, panic, or formatting code entered.
* **Static reachability.** From every backend entry symbol it walks direct
  calls and tail jumps in the linked executable and reports reachable
  formatting and panic machinery, division, atomic, and memory-helper sites
  that the traced steady state did not happen to execute.

The trace is deterministic user-mode machine code, independent of host
contention. It is structural evidence for the plan's codegen audit, never a
throughput measurement. Annotated per-region instruction listings are
retained beside the JSON report.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import signal
import sys
import tarfile
import tempfile
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
ALLOCATOR_ROOT = ROOT / "compat/allocator"
REPORT_ROOT = ROOT / "compat/reports/allocator/x86_64/codegen-audit"
SCHEMA = 1
KIND = "crabc-mimalloc-x86_64-codegen-audit"


def _load(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


engine = _load("crabc_allocator_perf_engine_x86_64", ALLOCATOR_ROOT / "perf_engine_x86_64.py")
shared = engine.shared
HarnessError = engine.HarnessError

ENTRY_SYMBOLS = (
    "crabc_allocator_engine_malloc",
    "crabc_allocator_engine_free",
    "crabc_allocator_engine_calloc",
    "crabc_allocator_engine_realloc",
    "crabc_allocator_engine_aligned",
    "crabc_allocator_engine_usable_size",
    "crabc_allocator_engine_thread_init",
    "crabc_allocator_engine_thread_done",
)


@dataclass(frozen=True)
class Scenario:
    name: str
    workload: str
    params: Mapping[str, int]
    regions: tuple[str, ...]
    measures: str


# Regions pair consecutive int3 markers in execution order.
SCENARIOS = (
    Scenario("local_64", "trace_local", {"size": 64}, ("malloc", "free"), "initial-thread small local allocation and free"),
    Scenario("local_1024", "trace_local", {"size": 1024}, ("malloc", "free"), "initial-thread small local allocation and free"),
    Scenario("local_32768", "trace_local", {"size": 32768}, ("malloc", "free"), "initial-thread medium local allocation and free"),
    Scenario("worker_64", "trace_worker", {"size": 64}, ("malloc", "free"), "attached later-thread local allocation and free"),
    Scenario("calloc_64", "trace_calloc", {"size": 64}, ("calloc",), "small zeroing allocation"),
    Scenario("calloc_4096", "trace_calloc", {"size": 4096}, ("calloc",), "zeroing allocation"),
    Scenario("aligned_64_at_64", "trace_aligned", {"size": 64, "alignment": 64}, ("aligned_alloc", "free"), "natural aligned allocation"),
    Scenario("aligned_256_at_4096", "trace_aligned", {"size": 256, "alignment": 4096}, ("aligned_alloc", "free"), "over-aligned allocation and interior-pointer free"),
    Scenario("realloc_move_1024", "trace_realloc_move", {"size": 1024}, ("realloc",), "moving reallocation with bounded copy"),
    Scenario("realloc_inplace_1024", "trace_realloc_inplace", {"size": 1024}, ("realloc",), "in-place reallocation reuse"),
    Scenario("usable_size_64", "trace_usable_size", {"size": 64}, ("usable_size",), "pointer-to-page usable-size lookup"),
    Scenario("remote_free_64", "trace_remote_free", {"size": 64, "count": 64}, ("remote_free", "owner_collect_64_mallocs"), "cross-thread free publication and the owner's collecting allocations"),
    Scenario("thread_lifecycle", "trace_thread_lifecycle", {"size": 64}, ("thread_init", "thread_done"), "later-thread attach and owner finish"),
)

STEP_LIMIT = 2_000_000


# ---- symbols and disassembly -------------------------------------------------


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    text: str
    target: int | None


class Image:
    """Symbolized disassembly of one static executable."""

    def __init__(self, binary: Path, nm: str, objdump: str) -> None:
        self.binary = binary
        symbols = self._symbols(binary, nm)
        self.starts = [start for start, _, _ in symbols]
        self.symbols = symbols
        self.by_name: dict[str, tuple[int, int]] = {}
        for start, end, name in symbols:
            self.by_name.setdefault(name, (start, end))
        self.instructions = self._disassemble(binary, objdump)
        self.int3 = frozenset(address for address, item in self.instructions.items() if item.mnemonic == "int3")
        self.data_symbols = self._symbols(binary, nm, kinds="dDbBrRvV")
        self.data_starts = [start for start, _, _ in self.data_symbols]

    @staticmethod
    def _symbols(binary: Path, nm: str, kinds: str = "tTwWiI") -> list[tuple[int, int, str]]:
        record = shared.command_record((nm, "-n", "-S", "--defined-only", "-C", str(binary)), cwd=ROOT)
        shared.require_success(record, "symbol table inspection")
        raw: list[tuple[int, int | None, str]] = []
        for line in str(record["stdout"]).splitlines():
            match = re.match(rf"^([0-9a-f]+)(?: ([0-9a-f]+))? ([{kinds}]) (.+)$", line)
            if match is None:
                continue
            address = int(match.group(1), 16)
            size = int(match.group(2), 16) if match.group(2) else None
            raw.append((address, size, match.group(4)))
        raw.sort(key=lambda item: (item[0], -(item[1] or 0)))
        result: list[tuple[int, int, str]] = []
        for index, (address, size, name) in enumerate(raw):
            if result and result[-1][0] == address:
                continue
            following = next((item[0] for item in raw[index + 1:] if item[0] > address), address + (size or 1))
            end = address + size if size else following
            result.append((address, end, name))
        return result

    @staticmethod
    def _disassemble(binary: Path, objdump: str) -> dict[int, Instruction]:
        record = shared.command_record(
            (objdump, "-d", "-w", "--no-show-raw-insn", "-C", "-M", "att", str(binary)), cwd=ROOT
        )
        shared.require_success(record, "disassembly")
        instructions: dict[int, Instruction] = {}
        pattern = re.compile(r"^\s*([0-9a-f]+):\s+(.*?)\s*$")
        for line in str(record["stdout"]).splitlines():
            match = pattern.match(line)
            if match is None:
                continue
            address = int(match.group(1), 16)
            text = match.group(2)
            if not text or text.startswith("(bad)"):
                continue
            parts = text.split(None, 1)
            mnemonic = parts[0]
            operands = parts[1] if len(parts) > 1 else ""
            # Keep prefixes (lock, rep, bnd, notrack, data16, cs) with their opcode.
            while mnemonic in {"lock", "rep", "repz", "repnz", "repe", "repne", "bnd", "notrack", "data16", "cs", "ds"} and operands:
                inner = operands.split(None, 1)
                mnemonic = f"{mnemonic} {inner[0]}"
                operands = inner[1] if len(inner) > 1 else ""
            target = None
            target_match = re.match(r"^([0-9a-f]+) <", operands)
            if target_match and (mnemonic.split()[-1].startswith(("call", "jmp")) or mnemonic.split()[-1].startswith("j")):
                target = int(target_match.group(1), 16)
            instructions[address] = Instruction(address, mnemonic, operands, text, target)
        if not instructions:
            raise HarnessError(f"objdump produced no instructions for {binary}")
        return instructions

    def function_at(self, address: int) -> str:
        index = bisect_right(self.starts, address) - 1
        if index >= 0:
            start, end, name = self.symbols[index]
            if start <= address < end:
                return name
        return f"<unknown:{address:#x}>"

    def data_symbol_at(self, address: int) -> str | None:
        index = bisect_right(self.data_starts, address) - 1
        if index >= 0:
            start, end, name = self.data_symbols[index]
            if start <= address < end:
                return f"{name}+{address - start:#x}"
        return None

    def function_range(self, name: str) -> tuple[int, int]:
        if name not in self.by_name:
            raise HarnessError(f"{self.binary.name} lacks symbol {name}")
        return self.by_name[name]


# ---- instruction classes -----------------------------------------------------


def base_mnemonic(item: Instruction) -> str:
    return item.mnemonic.split()[-1]


def has_memory_operand(operands: str) -> bool:
    """AT&T memory operand: base/index form or a segment-relative address."""

    return "(" in operands or re.search(r"%[fg]s:", operands) is not None


def is_atomic_rmw(item: Instruction) -> bool:
    if item.mnemonic.startswith("lock "):
        return True
    # xchg with a memory operand is implicitly locked (a full barrier) on x86;
    # a Rust SeqCst store compiles to exactly this form.
    return base_mnemonic(item).startswith("xchg") and has_memory_operand(item.operands)


REGISTER_ALIASES = {
    **{f"%{name}": name for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")},
}
MEMORY_OPERAND = re.compile(
    r"^(?:%(?P<segment>[fg]s):)?(?P<displacement>-?0x[0-9a-f]+|-?[0-9]+)?"
    r"(?:\((?P<base>%[a-z0-9]+)?(?:,(?P<index>%[a-z0-9]+)(?:,(?P<scale>[1248]))?)?\))?$"
)


def split_operands(operands: str) -> list[str]:
    text = operands.split("#", 1)[0].strip()
    result, depth, current = [], 0, ""
    for character in text:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            result.append(current.strip())
            current = ""
        else:
            current += character
    if current.strip():
        result.append(current.strip())
    return result


def effective_address(item: Instruction, registers: "UserRegisters") -> tuple[int, str] | None:
    """The memory target of one atomic instruction at its pre-execution state."""

    comment = re.search(r"#\s*([0-9a-f]+)", item.operands)
    for operand in split_operands(item.operands):
        if operand.startswith("%") and ":" not in operand:
            continue
        if operand.startswith("$"):
            continue
        match = MEMORY_OPERAND.match(operand)
        if match is None or (match.group("base") is None and match.group("segment") is None and match.group("displacement") is None):
            continue
        displacement = int(match.group("displacement") or "0", 0)
        if match.group("base") == "%rip":
            if comment is None:
                return None
            return int(comment.group(1), 16), "static"
        address = displacement
        for role in ("base", "index"):
            register = match.group(role)
            if register is None:
                continue
            name = REGISTER_ALIASES.get(register)
            if name is None:
                return None
            value = getattr(registers, name)
            address += value * (int(match.group("scale") or "1") if role == "index" else 1)
        if match.group("segment") == "fs":
            return (registers.fs_base + address) & 0xFFFF_FFFF_FFFF_FFFF, "thread-local"
        return address & 0xFFFF_FFFF_FFFF_FFFF, "memory"
    return None


def stack_allocation(item: Instruction) -> int:
    match = re.fullmatch(r"\$0x([0-9a-f]+),%rsp", item.operands)
    if base_mnemonic(item) == "sub" and match is not None:
        return int(match.group(1), 16)
    return 0


def is_fence(item: Instruction) -> bool:
    return base_mnemonic(item) in {"mfence", "lfence", "sfence"}


def is_division(item: Instruction) -> bool:
    return re.fullmatch(r"i?div[bwlq]?", base_mnemonic(item)) is not None


def is_call(item: Instruction) -> bool:
    return base_mnemonic(item).startswith("call")


def is_string_op(item: Instruction) -> bool:
    return item.mnemonic.startswith("rep") and any(op in item.mnemonic for op in ("movs", "stos", "cmps", "scas"))


def accesses_thread_pointer(item: Instruction) -> bool:
    return "%fs:" in item.operands


FORMATTING = re.compile(r"core::fmt|alloc::fmt|<.* as core::fmt::|::fmt\b|printf|vfprintf|snprintf|_mi_vsnprintf|_mi_fprintf|_mi_warning_message|_mi_error_message|_mi_verbose_message|mi_vfprintf|mi_printf")
PANIC = re.compile(r"core::panicking|panic_bounds_check|unwrap_failed|expect_failed|slice_(start|end)_index|slice_index_order_fail|core::option::|core::result::unwrap|rust_begin_unwind|__rust_start_panic|_mi_assert_fail")
MEMORY_HELPER = re.compile(r"^(memset|memcpy|memmove|__memcpy_fwd|bzero|explicit_bzero|_mi_memcpy|_mi_memzero|_mi_memcpy_aligned|_mi_memzero_aligned|compiler_builtins::mem::.*)$")


# ---- ptrace ------------------------------------------------------------------


PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACECLONE = 0x8
PTRACE_O_EXITKILL = 0x100000
PTRACE_EVENT_CLONE = 3
WALL = 0x40000000


class UserRegisters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
    )]


def libc_ptrace():
    library = ctypes.CDLL(None, use_errno=True)
    function = library.ptrace
    function.restype = ctypes.c_long
    function.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    return function


@dataclass
class Region:
    """Retired RIPs of one marker-bracketed region plus atomic targets."""

    rips: list[int]
    # position in `rips` -> (address, kind, stack pointer)
    atomic_targets: dict[int, tuple[int, str, int]]


def trace_scenario(
    binary: Path, image: Image, scenario: Scenario, scratch: Path, cpu: int
) -> list[Region]:
    """Return the retired-RIP sequence of every marker-bracketed region."""

    ptrace = libc_ptrace()

    def call(request: int, pid: int, address: int = 0, data: Any = 0) -> int:
        ctypes.set_errno(0)
        result = ptrace(request, pid, ctypes.c_void_p(address), data if isinstance(data, ctypes.c_void_p) else ctypes.c_void_p(data))
        if result == -1 and ctypes.get_errno() != 0:
            raise HarnessError(f"ptrace request {request} on {pid} failed: {os.strerror(ctypes.get_errno())}")
        return result

    arguments = [scenario.workload, *(f"{key}={value}" for key, value in sorted(scenario.params.items()))]
    stdout_path = scratch / f"{scenario.name}.stdout"
    stderr_path = scratch / f"{scenario.name}.stderr"
    child = os.fork()
    if child == 0:
        try:
            os.sched_setaffinity(0, {cpu})
            stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            if ptrace(PTRACE_TRACEME, 0, None, None) != 0:
                os._exit(125)
            os.execve(str(binary), [str(binary), *arguments], engine.clean_environment())
        except BaseException:  # noqa: BLE001
            os._exit(126)
    _, status = os.waitpid(child, 0)
    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP:
        raise HarnessError(f"traced fixture did not stop at exec: {status:#x}")
    call(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL)
    call(PTRACE_CONT, child, 0, 0)
    regions: list[Region] = []
    markers = 0
    registers = UserRegisters()
    finished = False
    try:
        while True:
            tid, status = os.waitpid(-1, WALL)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if tid == child:
                    finished = True
                    if os.WIFSIGNALED(status) or os.WEXITSTATUS(status) != 0:
                        detail = stderr_path.read_text(errors="replace")[:512] if stderr_path.exists() else ""
                        raise HarnessError(f"traced fixture {scenario.name} failed ({status:#x}): {detail}")
                    break
                continue
            if not os.WIFSTOPPED(status):
                continue
            stop = os.WSTOPSIG(status)
            event = status >> 16
            if stop == signal.SIGTRAP and event == PTRACE_EVENT_CLONE:
                call(PTRACE_CONT, tid, 0, 0)
                continue
            if stop == signal.SIGSTOP:
                call(PTRACE_CONT, tid, 0, 0)
                continue
            if stop == signal.SIGTRAP and event == 0:
                markers += 1
                if markers % 2 == 1:
                    rips: list[int] = []
                    targets: dict[int, tuple[int, str, int]] = {}
                    while True:
                        call(PTRACE_GETREGS, tid, 0, ctypes.c_void_p(ctypes.addressof(registers)))
                        rip = registers.rip
                        if rip in image.int3:
                            break
                        item = image.instructions.get(rip)
                        if item is not None and is_atomic_rmw(item):
                            target = effective_address(item, registers)
                            if target is not None:
                                targets[len(rips)] = (target[0], target[1], registers.rsp)
                        rips.append(rip)
                        if len(rips) > STEP_LIMIT:
                            raise HarnessError(f"{scenario.name} exceeded the single-step limit")
                        call(PTRACE_SINGLESTEP, tid, 0, 0)
                        _, step = os.waitpid(tid, WALL)
                        if not os.WIFSTOPPED(step) or os.WSTOPSIG(step) != signal.SIGTRAP:
                            raise HarnessError(f"{scenario.name} left single-step with status {step:#x}")
                    regions.append(Region(rips, targets))
                call(PTRACE_CONT, tid, 0, 0)
                continue
            call(PTRACE_CONT, tid, 0, stop)
    finally:
        if not finished:
            try:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
    if len(regions) != len(scenario.regions) or markers != 2 * len(scenario.regions):
        raise HarnessError(f"{scenario.name} traced {len(regions)} regions from {markers} markers; expected {len(scenario.regions)}")
    return regions


# ---- analysis ----------------------------------------------------------------


def collapse(rips: Sequence[int]) -> list[tuple[int, int]]:
    """Fold repeated single-steps of one rep-string instruction."""

    result: list[tuple[int, int]] = []
    for rip in rips:
        if result and result[-1][0] == rip:
            result[-1] = (rip, result[-1][1] + 1)
        else:
            result.append((rip, 1))
    return result


def classify_target(image: Image, address: int, kind: str, stack_pointer: int) -> str:
    """Name an atomic target: thread-local, stack, a named static, or dynamic memory."""

    if kind == "thread-local":
        return "thread-local"
    if abs(address - stack_pointer) < (1 << 20):
        return "stack"
    symbol = image.data_symbol_at(address)
    if symbol is not None:
        return f"static:{symbol}"
    return "dynamic"


def analyze_region(image: Image, region: Region) -> tuple[dict[str, Any], list[str]]:
    rips = region.rips
    atomic_targets: dict[str, int] = {}
    for address, kind, stack_pointer in region.atomic_targets.values():
        name = classify_target(image, address, kind, stack_pointer)
        atomic_targets[name] = atomic_targets.get(name, 0) + 1
    executed = collapse(rips)
    functions: dict[str, int] = {}
    calls: dict[tuple[str, str], int] = {}
    classes: dict[str, dict[tuple[str, str], int]] = {key: {} for key in ("atomic_rmw", "fences", "divisions", "string_ops", "syscalls")}
    thread_pointer = 0
    pushes = 0
    stack_bytes = 0
    listing = []
    entered_formatting: set[str] = set()
    entered_panic: set[str] = set()
    entered_memory: set[str] = set()
    previous: Instruction | None = None
    previous_function: str | None = None
    for rip, repeats in executed:
        item = image.instructions.get(rip)
        function = image.function_at(rip)
        functions[function] = functions.get(function, 0) + 1
        if previous is not None and previous_function is not None:
            # A call, or a jump to another symbol's first instruction (a
            # tail call), transfers control to a non-inlined helper.
            tail_call = (
                base_mnemonic(previous).startswith("jmp")
                and function != previous_function
                and function in image.by_name
                and image.by_name[function][0] == rip
            )
            if is_call(previous) or tail_call:
                key = (previous_function, function)
                calls[key] = calls.get(key, 0) + 1
        if FORMATTING.search(function):
            entered_formatting.add(function)
        if PANIC.search(function):
            entered_panic.add(function)
        if MEMORY_HELPER.match(function):
            entered_memory.add(function)
        text = item.text if item is not None else "<no disassembly>"
        listing.append(f"{rip:#x} {function}: {text}" + (f"  x{repeats}" if repeats > 1 else ""))
        previous = item
        previous_function = function
        if item is None:
            continue
        for name, predicate in (("atomic_rmw", is_atomic_rmw), ("fences", is_fence), ("divisions", is_division), ("string_ops", is_string_op)):
            if predicate(item):
                entry = (function, item.text)
                classes[name][entry] = classes[name].get(entry, 0) + 1
        if base_mnemonic(item) == "syscall":
            entry = (function, item.text)
            classes["syscalls"][entry] = classes["syscalls"].get(entry, 0) + 1
        if accesses_thread_pointer(item):
            thread_pointer += 1
        if base_mnemonic(item).startswith("push"):
            pushes += 1
        stack_bytes += stack_allocation(item)
    order = []
    for rip, _ in executed:
        name = image.function_at(rip)
        if name not in order:
            order.append(name)
    summary = {
        "instructions": len(executed),
        "single_steps": len(rips),
        "functions": [{"name": name, "instructions": functions[name]} for name in order],
        "function_count": len(functions),
        "call_transitions": [{"from": caller, "to": callee, "count": count} for (caller, callee), count in calls.items()],
        "thread_pointer_accesses": thread_pointer,
        "pushes": pushes,
        "stack_bytes_allocated": stack_bytes,
        "entered_formatting": sorted(entered_formatting),
        "entered_panic": sorted(entered_panic),
        "entered_memory_helpers": sorted(entered_memory),
        "atomic_rmw_targets": dict(sorted(atomic_targets.items())),
        "atomic_rmw_non_thread_local": sum(count for name, count in atomic_targets.items() if name not in {"thread-local", "stack"}),
    }
    for name, values in classes.items():
        summary[name] = [{"function": function, "instruction": text, "count": count} for (function, text), count in values.items()]
    return summary, listing


def static_reachability(image: Image, entry: str) -> dict[str, Any]:
    """Direct-call/tail-jump closure of one entry symbol in the linked image."""

    start, _ = image.function_range(entry)
    pending = [image.function_at(start)]
    seen: set[str] = set()
    indirect = 0
    counts = {"atomic_rmw": 0, "fences": 0, "divisions": 0, "string_ops": 0, "syscalls": 0}
    instructions = 0
    direct_callees: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen or name not in image.by_name:
            continue
        seen.add(name)
        low, high = image.by_name[name]
        for address in range(low, high):
            item = image.instructions.get(address)
            if item is None:
                continue
            instructions += 1
            counts["atomic_rmw"] += is_atomic_rmw(item)
            counts["fences"] += is_fence(item)
            counts["divisions"] += is_division(item)
            counts["string_ops"] += is_string_op(item)
            counts["syscalls"] += base_mnemonic(item) == "syscall"
            mnemonic = base_mnemonic(item)
            if (mnemonic.startswith("call") or mnemonic.startswith("jmp")) and item.operands.startswith("*"):
                indirect += 1
            if item.target is not None and (mnemonic.startswith("call") or mnemonic.startswith("jmp")):
                callee = image.function_at(item.target)
                if callee != name:
                    if name == image.function_at(start):
                        direct_callees.add(callee)
                    pending.append(callee)
    return {
        "reachable_functions": len(seen),
        "reachable_instructions": instructions,
        "indirect_calls_or_jumps": indirect,
        "entry_direct_callees": sorted(direct_callees),
        "reachable_formatting": sorted(name for name in seen if FORMATTING.search(name)),
        "reachable_panic": sorted(name for name in seen if PANIC.search(name)),
        "reachable_memory_helpers": sorted(name for name in seen if MEMORY_HELPER.match(name)),
        **{f"reachable_{key}_sites": value for key, value in counts.items()},
    }


def compare_regions(c_summary: Mapping[str, Any], rust_summary: Mapping[str, Any]) -> dict[str, Any]:
    def total(summary: Mapping[str, Any], key: str) -> int:
        return sum(entry["count"] for entry in summary[key])

    def calls(summary: Mapping[str, Any]) -> int:
        return sum(entry["count"] for entry in summary["call_transitions"])

    result = {
        "instructions": {"pinned_c": c_summary["instructions"], "rust_engine": rust_summary["instructions"]},
        "instruction_ratio_rust_over_c": rust_summary["instructions"] / max(1, c_summary["instructions"]),
        "functions_entered": {"pinned_c": c_summary["function_count"], "rust_engine": rust_summary["function_count"]},
        "calls": {"pinned_c": calls(c_summary), "rust_engine": calls(rust_summary)},
    }
    for key in ("atomic_rmw", "fences", "divisions", "string_ops", "syscalls"):
        result[key] = {"pinned_c": total(c_summary, key), "rust_engine": total(rust_summary, key)}
    for key in ("thread_pointer_accesses", "pushes", "stack_bytes_allocated", "atomic_rmw_non_thread_local"):
        result[key] = {"pinned_c": c_summary[key], "rust_engine": rust_summary[key]}
    # Each flag names one class of structural cost the plan's codegen audit
    # looks for: helpers the source inlines (calls), checks (panic paths),
    # fences/atomics, division, formatting, and zeroing/copying (string
    # operations or memory helpers) that the pinned C path does not execute.
    excess = []
    for key in ("calls", "atomic_rmw", "atomic_rmw_non_thread_local", "fences", "divisions", "string_ops", "syscalls"):
        if result[key]["rust_engine"] > result[key]["pinned_c"]:
            excess.append(f"{key}: rust {result[key]['rust_engine']} > pinned C {result[key]['pinned_c']}")
    for key in ("entered_formatting", "entered_panic"):
        if rust_summary[key]:
            excess.append(f"{key}: {', '.join(rust_summary[key])}")
    extra_helpers = sorted(set(rust_summary["entered_memory_helpers"]) - set(c_summary["entered_memory_helpers"]))
    if extra_helpers:
        excess.append(f"entered_memory_helpers: {', '.join(extra_helpers)}")
    result["rust_excess"] = excess
    return result


# ---- driver ------------------------------------------------------------------


def run(arguments: argparse.Namespace) -> Path:
    engine.shared.require_native_x86_64()
    manifest = engine.load_manifest()
    label = shared.validate_label(arguments.label)
    compiler = shared.require_tool("musl-gcc")
    readelf = shared.require_tool("readelf")
    nm = shared.require_tool("nm")
    objdump = shared.require_tool("objdump")
    pin = shared.load_pin()
    archive = shared.fetch_archive(pin, offline=arguments.offline)
    artifacts = REPORT_ROOT / f"{label}.artifacts"
    if artifacts.exists():
        import shutil

        shutil.rmtree(artifacts)
    artifacts.mkdir(parents=True)
    allowed = sorted(os.sched_getaffinity(0))
    cpu = arguments.cpu if arguments.cpu is not None else allowed[0]
    if cpu not in allowed:
        raise HarnessError(f"CPU {cpu} is not allowed")
    selected = [scenario for scenario in SCENARIOS if not arguments.only or scenario.name in arguments.only]
    if arguments.only and len(selected) != len(set(arguments.only)):
        raise HarnessError("unknown --only scenario")
    report: dict[str, Any] = {"schema": SCHEMA, "kind": KIND, "label": label, "status": "pending"}
    with tempfile.TemporaryDirectory(prefix="crabc-codegen-audit-") as temporary:
        temporary_path = Path(temporary)
        source = shared.safe_extract(archive, temporary_path / "source", pin["archive_root"])
        report["provenance"] = {
            "git": engine.git_provenance(),
            "tools": engine.tool_versions(),
            "inputs": engine.input_provenance(archive, pin),
        }
        built = engine.build_lanes(manifest, source, artifacts, compiler=compiler, readelf=readelf)
        report["lanes"] = {lane: {"executable": built["records"][lane]["executable"]} for lane in engine.LANES}
        images = {lane: Image(built["binaries"][lane], nm, objdump) for lane in engine.LANES}
        report["static"] = {
            lane: {entry: static_reachability(images[lane], entry) for entry in ENTRY_SYMBOLS}
            for lane in engine.LANES
        }
        scratch = temporary_path / "trace"
        scratch.mkdir()
        scenarios: dict[str, Any] = {}
        for scenario in selected:
            per_lane: dict[str, Any] = {}
            for lane in engine.LANES:
                regions = trace_scenario(built["binaries"][lane], images[lane], scenario, scratch, cpu)
                lane_regions = {}
                for region_name, region in zip(scenario.regions, regions):
                    summary, listing = analyze_region(images[lane], region)
                    listing_path = artifacts / f"trace-{scenario.name}-{region_name}-{lane}.txt"
                    listing_path.write_text("\n".join(listing) + "\n", encoding="utf-8")
                    summary["listing"] = listing_path.name
                    lane_regions[region_name] = summary
                per_lane[lane] = lane_regions
            scenarios[scenario.name] = {
                "workload": scenario.workload,
                "params": dict(scenario.params),
                "measures": scenario.measures,
                "lanes": per_lane,
                "comparison": {
                    region: compare_regions(per_lane["pinned_c"][region], per_lane["rust_engine"][region])
                    for region in scenario.regions
                },
            }
            print(f"traced {scenario.name}", file=sys.stderr, flush=True)
        report["scenarios"] = scenarios
    report["status"] = "ok"
    path = REPORT_ROOT / f"{label}.json"
    engine.atomic_write_json(path, report)
    return path


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--label", default="codegen", help="report label")
    parser.add_argument("--offline", action="store_true", help="require the pinned C archive in the local cache")
    parser.add_argument("--cpu", type=int, default=None, help="allowed CPU for traced fixtures")
    parser.add_argument("--only", nargs="+", default=None, help="trace only these scenarios")
    arguments = parser.parse_args(argv)
    shared.validate_label(arguments.label)
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        path = run(arguments)
    except (HarnessError, OSError, tarfile.TarError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
