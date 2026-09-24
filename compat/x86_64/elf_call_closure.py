#!/usr/bin/env python3
"""Behavior facts about the machine code a final x86-64 ELF runs from a root.

Native C runners used to pin codegen shape: one ``raw_syscall::syscallN``
archive member, a direct ``call`` from a wrapper to a named helper, an atomic
instruction inside the wrapper's own symbol. Rust is free to inline or outline
any of those, so the pins failed as optimizer choices drifted while the
behavior they protected stayed intact.

This reader asks the behavior question instead. It disassembles one linked
candidate once, takes the *call closure* of a root symbol (the root plus every
function reachable through direct ``call``/``jmp``/``jcc`` edges inside the
candidate), and reports facts about that closure:

* every ``syscall`` instruction with the values its Linux argument registers
  (``rax`` number, ``rdi``, ``rsi``, ``rdx``, ``r10``, ``r8``, ``r9``) can hold
  on arrival, resolved backward through register moves, immediates, and the
  call sites of the functions that receive them as arguments;
* which named functions are in the closure;
* the normalized instruction text, for atomic, TLS, or immediate checks.

Register resolution is a small reaching-definition walk over each function's
direct control flow. A value it cannot name (loaded from memory, computed,
or passed through an indirect call) is ``?``; an argument the root itself
receives is ``arg:<register>``. Assertions only admit facts the walk proves, so
an unknown value never satisfies a required one, and ``--syscalls-only``
rejects a syscall whose number is unknown.

Use ``check`` in runners and ``dump`` to see the closure while writing one.
"""

from __future__ import annotations

import argparse
import bisect
import dataclasses
import itertools
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence


class ClosureError(RuntimeError):
    """The candidate cannot be read, or an assertion about it fails."""


SYSCALL_REGISTERS = ("rax", "rdi", "rsi", "rdx", "r10", "r8", "r9")
SYSCALL_NAMES = {"nr": "rax", "a1": "rdi", "a2": "rsi", "a3": "rdx", "a4": "r10", "a5": "r8", "a6": "r9"}
CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
PREFIXES = {"lock", "rep", "repz", "repe", "repnz", "repne", "notrack", "bnd",
            "cs", "ds", "es", "ss", "fs", "gs", "data16", "addr32", "rex", "rex.w"}
NO_REGISTER_WRITE = ("cmp", "test", "push", "ucomis", "comis", "ptest", "prefetch", "nop", "endbr",
                     "clflush", "sfence", "lfence", "mfence", "pause", "ud2", "hlt")

_REGISTER_ALIASES: dict[str, tuple[str, int]] = {}
for _full, _names in {
    "rax": ("rax", "eax", "ax", "al", "ah"), "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"), "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"), "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"), "rsp": ("rsp", "esp", "sp", "spl"),
}.items():
    for _name, _width in zip(_names, (64, 32, 16, 8, 8)):
        _REGISTER_ALIASES[_name] = (_full, _width)
for _number in range(8, 16):
    for _suffix, _width in (("", 64), ("d", 32), ("w", 16), ("b", 8)):
        _REGISTER_ALIASES[f"r{_number}{_suffix}"] = (f"r{_number}", _width)

_HEADER = re.compile(r"^(?P<address>[0-9a-f]+) <(?P<name>.+)>:$")
_LINE = re.compile(r"^\s*(?P<address>[0-9a-f]+):\s*(?P<text>\S.*?)\s*$")
# Demangled Rust names may themselves contain `<...>`; the optional offset and
# the closing bracket anchor the end.
_TARGET = re.compile(r"^(?P<address>[0-9a-f]+) <(?P<name>.+?)(?:\+0x[0-9a-f]+)?>$")
_IMMEDIATE = re.compile(r"^\$(?P<value>-?(?:0x)?[0-9a-f]+)$")


def register(operand: str) -> tuple[str, int] | None:
    """Return the full register and access width named by one operand."""

    if operand.startswith("%"):
        return _REGISTER_ALIASES.get(operand[1:])
    return None


def split_operands(text: str) -> list[str]:
    """Split AT&T operands on commas outside memory parentheses."""

    operands, depth, current = [], 0, ""
    for character in text:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            operands.append(current.strip())
            current = ""
        else:
            current += character
    if current.strip():
        operands.append(current.strip())
    return operands


@dataclasses.dataclass(frozen=True)
class Instruction:
    address: int
    prefixes: tuple[str, ...]
    mnemonic: str
    operands: tuple[str, ...]
    comment: str
    target: int | None
    target_name: str | None

    @property
    def text(self) -> str:
        """Normalized ``prefix mnemonic operands`` text used by instruction checks."""

        return " ".join((*self.prefixes, self.mnemonic, ",".join(self.operands))).strip()

    @property
    def is_call(self) -> bool:
        return self.mnemonic.startswith("call")

    @property
    def is_jump(self) -> bool:
        return self.mnemonic.startswith("j")

    @property
    def is_unconditional_jump(self) -> bool:
        return self.mnemonic in {"jmp", "jmpq"}

    @property
    def ends_flow(self) -> bool:
        return self.is_unconditional_jump or self.mnemonic in {"ret", "retq", "ud2", "hlt"}

    @property
    def indirect(self) -> bool:
        return (self.is_call or self.is_jump) and bool(self.operands) and self.operands[0].startswith("*")


def parse_instruction(address: int, text: str) -> Instruction:
    comment = ""
    if "#" in text:
        text, comment = (part.strip() for part in text.split("#", 1))
    words = text.split()
    prefixes: list[str] = []
    while words and words[0] in PREFIXES and len(words) > 1:
        prefixes.append(words.pop(0))
    mnemonic = words[0] if words else ""
    rest = text.split(None, len(prefixes) + 1)[len(prefixes) + 1:] if words else []
    operand_text = rest[0] if rest else ""
    target = target_name = None
    if mnemonic.startswith(("call", "j")):
        match = _TARGET.match(operand_text.strip())
        if match is not None:
            target, target_name = int(match.group("address"), 16), match.group("name")
            return Instruction(address, tuple(prefixes), mnemonic, (operand_text.strip(),), comment, target, target_name)
    return Instruction(address, tuple(prefixes), mnemonic, tuple(split_operands(operand_text)), comment, None, None)


@dataclasses.dataclass
class Function:
    name: str
    start: int
    instructions: list[Instruction]

    def __post_init__(self) -> None:
        self.index = {instruction.address: position for position, instruction in enumerate(self.instructions)}
        self.predecessors: list[list[int]] = [[] for _ in self.instructions]
        for position, instruction in enumerate(self.instructions):
            if position + 1 < len(self.instructions) and not instruction.ends_flow:
                self.predecessors[position + 1].append(position)
            if instruction.is_jump and instruction.target in self.index:
                self.predecessors[self.index[instruction.target]].append(position)


def parse_disassembly(text: str) -> list[Function]:
    """Parse ``objdump -d -w -C --no-show-raw-insn`` output into functions."""

    functions: list[Function] = []
    current: Function | None = None
    for line in text.splitlines():
        header = _HEADER.match(line)
        if header is not None:
            current = Function(header.group("name"), int(header.group("address"), 16), [])
            functions.append(current)
            continue
        match = _LINE.match(line)
        if match is None or current is None:
            continue
        instruction_text = match.group("text")
        if instruction_text.startswith("(bad)") or instruction_text == "...":
            continue
        current.instructions.append(parse_instruction(int(match.group("address"), 16), instruction_text))
    for function in functions:
        function.__post_init__()
    return functions


@dataclasses.dataclass(frozen=True)
class Value:
    """One resolved register value: an integer, a root argument, or unknown."""

    kind: str  # "int", "arg", "addr", "?"
    number: int = 0
    width: int = 64
    name: str = ""

    def __str__(self) -> str:
        if self.kind == "int":
            return hex(self.number)
        if self.kind == "arg":
            return f"arg:{self.name}"
        if self.kind == "addr":
            return f"&{self.name}"
        return "?"

    def matches(self, expected: str) -> bool:
        if "|" in expected:
            return any(self.matches(alternative) for alternative in expected.split("|"))
        if expected == "*":
            return True
        if expected.startswith("arg:"):
            return self.kind == "arg" and self.name == expected[4:]
        if expected.startswith("&"):
            return self.kind == "addr" and self.name == expected[1:]
        if self.kind != "int":
            return False
        wanted = int(expected, 0)
        mask = (1 << self.width) - 1
        return (wanted & mask) == (self.number & mask)


UNKNOWN = Value("?")


@dataclasses.dataclass(frozen=True)
class Transform:
    """An immediate ``and``/``or``/``add`` applied to a register's prior value."""

    operation: str
    immediate: int
    width: int

    def apply(self, value: Value) -> list[Value]:
        mask = (1 << self.width) - 1
        if self.operation == "and":
            if value.kind == "int":
                return [Value("int", value.number & self.immediate & mask, self.width)]
            # An unknown value masked to at most four bits takes each subset.
            bits = [1 << bit for bit in range(self.width) if self.immediate >> bit & 1]
            if len(bits) > 4:
                return [UNKNOWN]
            return [Value("int", sum(chosen), self.width)
                    for count in range(len(bits) + 1) for chosen in itertools.combinations(bits, count)]
        if value.kind != "int":
            return [UNKNOWN]
        if self.operation == "or":
            return [Value("int", (value.number | self.immediate) & mask, self.width)]
        return [Value("int", (value.number + self.immediate) & mask, self.width)]


def apply_transforms(value: Value, transforms: Sequence[Transform]) -> list[Value]:
    values = [value]
    for transform in transforms:
        values = [result for item in values for result in transform.apply(item)]
    return values


@dataclasses.dataclass(frozen=True)
class SyscallEvent:
    function: str
    address: int
    registers: tuple[tuple[str, Value], ...]

    def value(self, name: str) -> Value:
        return dict(self.registers)[SYSCALL_NAMES.get(name, name)]

    def __str__(self) -> str:
        values = " ".join(f"{name}={value}" for name, value in self.registers)
        return f"{self.function}@{self.address:x} {values}"


class Candidate:
    """One disassembled ELF and its direct-transfer graph."""

    def __init__(self, functions: Sequence[Function], aliases: Mapping[int, Iterable[str]] = {}):
        self.functions = [function for function in functions if function.instructions]
        self.functions.sort(key=lambda function: function.start)
        self.starts = [function.start for function in self.functions]
        # Every symbol at a function's entry names it: objdump titles an
        # address with one alias (for example `__pthread_mutex_lock` for the
        # weak `pthread_mutex_lock`), and roots or reach checks may use any.
        self.names: dict[int, set[str]] = {function.start: {function.name} for function in self.functions}
        for address, names in aliases.items():
            if address in self.names:
                self.names[address].update(names)
        self.by_name: dict[str, list[Function]] = {}
        for function in self.functions:
            for name in self.names[function.start]:
                self.by_name.setdefault(name, []).append(function)
        self.callers: dict[int, list[tuple[Function, int]]] = {}
        for function in self.functions:
            for position, instruction in enumerate(function.instructions):
                if instruction.target is None:
                    continue
                callee = self.function_at(instruction.target)
                if callee is not None and callee is not function and instruction.target == callee.start:
                    self.callers.setdefault(callee.start, []).append((function, position))

    @classmethod
    def from_elf(cls, elf: Path, objdump: str = "objdump", nm: str = "nm") -> "Candidate":
        process = subprocess.run([objdump, "-d", "-w", "-C", "--no-show-raw-insn", str(elf)],
                                 check=False, capture_output=True, text=True)
        if process.returncode != 0:
            raise ClosureError(f"objdump could not disassemble {elf}: {process.stderr.strip()}")
        symbols = subprocess.run([nm, "-C", "--defined-only", "--format=posix", str(elf)],
                                 check=False, capture_output=True, text=True)
        if symbols.returncode != 0:
            raise ClosureError(f"nm could not read {elf}: {symbols.stderr.strip()}")
        aliases: dict[int, set[str]] = {}
        for line in symbols.stdout.splitlines():
            # POSIX nm: NAME TYPE VALUE [SIZE]; demangled names may contain spaces.
            match = re.match(r"^(?P<name>.+) (?P<kind>[TtWw]) (?P<value>[0-9a-f]+)(?: [0-9a-f]+)?$", line)
            if match is not None:
                aliases.setdefault(int(match.group("value"), 16), set()).add(match.group("name"))
        return cls(parse_disassembly(process.stdout), aliases)

    def function_at(self, address: int) -> Function | None:
        position = bisect.bisect_right(self.starts, address) - 1
        if position < 0:
            return None
        function = self.functions[position]
        last = function.instructions[-1].address
        return function if function.start <= address <= last else None

    def root(self, name: str) -> Function:
        matches = self.by_name.get(name, [])
        if len(matches) != 1:
            raise ClosureError(f"root {name} names {len(matches)} functions in the candidate")
        return matches[0]

    def address_references(self, instruction: Instruction) -> list[int]:
        """Function entry addresses an instruction materializes as data.

        A static executable passes a thread start routine or callback as
        ``lea sym(%rip)`` or as an absolute ``mov $addr``; both name the entry.
        """

        addresses = []
        if instruction.mnemonic.startswith("lea") and instruction.comment:
            match = re.match(r"([0-9a-f]+) <", instruction.comment)
            if match is not None:
                addresses.append(int(match.group(1), 16))
        elif instruction.mnemonic.startswith("mov") and instruction.operands:
            immediate = _IMMEDIATE.match(instruction.operands[0])
            if immediate is not None:
                addresses.append(int(immediate.group("value"), 16) & ((1 << 64) - 1))
        return [address for address in addresses
                if (function := self.function_at(address)) is not None and function.start == address]

    def closure(self, roots: Iterable[Function], exclude: Iterable[str] = (),
                follow_addresses: bool = False) -> list[Function]:
        """Return every function reachable from the roots by direct transfers.

        Functions named in ``exclude`` are neither entered nor reported, which
        cuts a closure at a separately qualified boundary such as ``exit``.
        With ``follow_addresses``, a function whose entry address is taken
        (a thread start routine or callback) is also reachable.
        """

        excluded = set(exclude)
        seen: dict[int, Function] = {}
        pending = list(roots)
        while pending:
            function = pending.pop()
            if function.start in seen or function.name in excluded:
                continue
            seen[function.start] = function
            for instruction in function.instructions:
                targets = [instruction.target] if instruction.target is not None else []
                if follow_addresses:
                    targets.extend(self.address_references(instruction))
                for target in targets:
                    callee = self.function_at(target)
                    if callee is not None and callee.start not in seen:
                        pending.append(callee)
        return sorted(seen.values(), key=lambda function: function.start)


class Resolver:
    """Resolve register values at an instruction inside one closure."""

    LIMIT = 256

    def __init__(self, candidate: Candidate, closure: Sequence[Function], roots: Sequence[Function]):
        self.candidate = candidate
        self.members = {function.start for function in closure}
        self.roots = {function.start for function in roots}

    def local(self, function: Function, position: int, name: str) -> set[Value | tuple]:
        """Values of ``name`` just before ``position``.

        ``("in", reg, transforms)`` stands for the function's incoming ``reg``
        after the listed immediate transforms (innermost first).
        """

        results: set[Value | tuple] = set()
        visited: set[tuple[int, str, tuple]] = set()
        pending = [(predecessor, name, ()) for predecessor in function.predecessors[position]]
        if not pending and position == 0:
            results.add(("in", name, ()))
        while pending:
            index, wanted, transforms = pending.pop()
            if (index, wanted, transforms) in visited:
                continue
            visited.add((index, wanted, transforms))
            defined = self.definition(function.instructions[index], wanted)
            if defined is None or isinstance(defined, (str, Transform)):
                if isinstance(defined, str):
                    wanted = defined
                elif isinstance(defined, Transform):
                    transforms = (defined,) + transforms
                if index == 0:
                    results.add(("in", wanted, transforms))
                pending.extend((predecessor, wanted, transforms) for predecessor in function.predecessors[index])
            else:
                for value in (defined if isinstance(defined, list) else [defined]):
                    results.update(apply_transforms(value, transforms))
            if len(results) > self.LIMIT:
                return {UNKNOWN}
        return results

    @staticmethod
    def definition(instruction: Instruction, name: str) -> "Value | str | Transform | None":
        """How ``instruction`` defines ``name``: a value, a source register, or not at all."""

        mnemonic = instruction.mnemonic
        operands = instruction.operands
        if instruction.is_call:
            return UNKNOWN if name in CALLER_SAVED else None
        if mnemonic == "syscall":
            return UNKNOWN if name in {"rax", "rcx", "r11"} else None
        if instruction.is_jump or mnemonic.startswith(NO_REGISTER_WRITE) or mnemonic in {"bt", "btl", "btq"}:
            return None
        if mnemonic.startswith(("cmpxchg",)) and name == "rax":
            return UNKNOWN
        if mnemonic.startswith(("mul", "div", "idiv", "rdtsc", "cqto", "cltd", "cwtd")) and name in {"rax", "rdx"}:
            return UNKNOWN
        if mnemonic in {"cltq", "cwtl", "cbtw"} and name == "rax":
            return UNKNOWN
        if mnemonic == "cpuid" and name in {"rax", "rbx", "rcx", "rdx"}:
            return UNKNOWN
        if mnemonic.startswith(("movs", "stos", "lods", "scas", "cmps")) and (
                not operands or any("%es:" in operand or "%ds:" in operand for operand in operands)):
            return UNKNOWN if name in {"rdi", "rsi", "rcx", "rax"} else None
        if mnemonic.startswith(("xchg", "xadd")) and any(
                (register(operand) or ("", 0))[0] == name for operand in operands):
            return UNKNOWN
        if not operands:
            return None
        destination = register(operands[-1])
        if destination is None or destination[0] != name:
            return None
        full, width = destination
        source = operands[0] if len(operands) > 1 else None
        if mnemonic in {"mov", "movl", "movq", "movabs", "movabsq"} and source is not None:
            immediate = _IMMEDIATE.match(source)
            if immediate is not None:
                number = int(immediate.group("value"), 16) & ((1 << 64) - 1)
                # A 32-bit write zero-extends; an 8- or 16-bit write leaves the
                # upper bits, so only its own width is known.
                return Value("int", number & ((1 << width) - 1), width)
            source_register = register(source)
            if source_register is not None and width >= 32:
                return source_register[0]
            return UNKNOWN
        if mnemonic.startswith(("movz", "movs")) and source is not None and register(source) is not None:
            return register(source)[0]
        if mnemonic.startswith(("xor", "sub")) and source is not None and register(source) == destination:
            return Value("int", 0, width)
        immediate = _IMMEDIATE.match(source or "")
        if immediate is not None and width >= 32 and mnemonic.rstrip("lq") in {"and", "or", "add"}:
            return Transform(mnemonic.rstrip("lq"), int(immediate.group("value"), 16) & ((1 << width) - 1), width)
        if mnemonic.startswith("lea") and "(%rip)" in (source or "") and instruction.comment:
            symbol = _TARGET.match(instruction.comment)
            if symbol is not None:
                return Value("addr", name=symbol.group("name"))
        return UNKNOWN

    def resolve(self, function: Function, position: int, names: Sequence[str], depth: int = 0,
                stack: tuple[int, ...] = ()) -> list[dict[str, Value]]:
        """Joint assignments of ``names`` before ``position``, one per calling context."""

        choices = []
        for name in names:
            values = sorted(self.local(function, position, name), key=str)
            choices.append(values or [UNKNOWN])
        assignments: list[dict[str, Value]] = []
        for combination in itertools.islice(itertools.product(*choices), self.LIMIT):
            incoming = {name: value for name, value in zip(names, combination) if isinstance(value, tuple)}
            fixed = {name: value for name, value in zip(names, combination) if isinstance(value, Value)}
            if not incoming:
                assignments.append(fixed)
                continue

            def bind(outer: Mapping[str, Value]) -> None:
                per_name = [[(name, result) for result in apply_transforms(outer[source], transforms)]
                            for name, (_, source, transforms) in incoming.items()]
                for chosen in itertools.islice(itertools.product(*per_name), self.LIMIT):
                    assignments.append({**fixed, **dict(chosen)})

            callers = [(caller, site) for caller, site in self.candidate.callers.get(function.start, [])
                       if caller.start in self.members]
            sources = sorted({source for _, source, _ in incoming.values()})
            if function.start in self.roots:
                bind({source: Value("arg", name=source) for source in sources})
            if not callers or depth >= 12 or function.start in stack:
                if function.start not in self.roots:
                    bind({source: UNKNOWN for source in sources})
                continue
            for caller, site in callers:
                for outer in self.resolve(caller, site, sources, depth + 1, stack + (function.start,)):
                    bind(outer)
        unique: dict[tuple, dict[str, Value]] = {}
        for assignment in assignments:
            unique.setdefault(tuple(sorted(assignment.items())), assignment)
            if len(unique) > self.LIMIT:
                break
        return list(unique.values())


@dataclasses.dataclass
class Closure:
    roots: list[Function]
    functions: list[Function]
    syscalls: list[SyscallEvent]

    aliases: Mapping[int, set[str]] = dataclasses.field(default_factory=dict)

    @property
    def names(self) -> set[str]:
        return {name for function in self.functions
                for name in self.aliases.get(function.start, {function.name})}

    def instructions(self) -> Iterable[tuple[Function, Instruction]]:
        for function in self.functions:
            for instruction in function.instructions:
                yield function, instruction


def closure_of(candidate: Candidate, roots: Sequence[str], exclude: Sequence[str] = (),
               follow_addresses: bool = False) -> Closure:
    root_functions = [candidate.root(name) for name in roots]
    functions = candidate.closure(root_functions, exclude, follow_addresses)
    resolver = Resolver(candidate, functions, root_functions)
    events: list[SyscallEvent] = []
    for function in functions:
        for position, instruction in enumerate(function.instructions):
            if instruction.mnemonic != "syscall":
                continue
            for assignment in resolver.resolve(function, position, SYSCALL_REGISTERS):
                events.append(SyscallEvent(function.name, instruction.address,
                                           tuple((name, assignment[name]) for name in SYSCALL_REGISTERS)))
    unique = {(event.address, event.registers): event for event in events}
    return Closure(root_functions, functions, sorted(unique.values(), key=lambda event: (event.address, str(event))),
                   candidate.names)


def parse_constraint(text: str) -> dict[str, str]:
    """Parse ``nr=13,a4=8`` or ``rax=13,r10=8`` syscall constraints."""

    result: dict[str, str] = {}
    for item in text.split(","):
        key, separator, value = item.partition("=")
        key = key.strip()
        if not separator or not value.strip():
            raise ClosureError(f"invalid syscall constraint item: {item!r}")
        register_name = SYSCALL_NAMES.get(key, key)
        if register_name not in SYSCALL_REGISTERS:
            raise ClosureError(f"unknown syscall constraint register: {key}")
        result[register_name] = value.strip()
    return result


def event_matches(event: SyscallEvent, constraint: Mapping[str, str]) -> bool:
    values = dict(event.registers)
    return all(values[name].matches(expected) for name, expected in constraint.items())


def check(closure: Closure, *, syscalls: Sequence[str] = (), no_syscalls: Sequence[str] = (),
          every_syscall: Sequence[str] = (), syscalls_only: Sequence[str] = (), reaches: Sequence[str] = (), not_reaches: Sequence[str] = (),
          instructions: Sequence[str] = (), no_instructions: Sequence[str] = ()) -> list[str]:
    """Return every failed assertion as one message."""

    failures: list[str] = []
    for text in syscalls:
        constraint = parse_constraint(text)
        if not any(event_matches(event, constraint) for event in closure.syscalls):
            failures.append(f"no reachable syscall with {text}")
    for text in no_syscalls:
        constraint = parse_constraint(text)
        for event in closure.syscalls:
            if event_matches(event, constraint):
                failures.append(f"forbidden syscall {text} reachable: {event}")
    for text in every_syscall:
        constraint = parse_constraint(text)
        for event in closure.syscalls:
            if not event_matches(event, constraint):
                failures.append(f"syscall does not satisfy {text}: {event}")
    if syscalls_only:
        allowed = {int(number, 0) for number in syscalls_only}
        for event in closure.syscalls:
            number = event.value("rax")
            if number.kind != "int" or number.number not in allowed:
                failures.append(f"syscall outside {','.join(syscalls_only)}: {event}")
    names = closure.names
    for name in reaches:
        if name not in names:
            failures.append(f"closure does not reach {name}")
    for name in not_reaches:
        if name in names:
            failures.append(f"closure reaches forbidden {name}")
    texts = [(function, instruction) for function, instruction in closure.instructions()]
    for pattern in instructions:
        expression = re.compile(pattern)
        if not any(expression.search(instruction.text) for _, instruction in texts):
            failures.append(f"no reachable instruction matches /{pattern}/")
    for pattern in no_instructions:
        expression = re.compile(pattern)
        for function, instruction in texts:
            if expression.search(instruction.text):
                failures.append(f"forbidden instruction /{pattern}/ in {function.name}@{instruction.address:x}: "
                                f"{instruction.text}")
    return failures


def describe(closure: Closure) -> str:
    lines = [f"roots: {' '.join(function.name for function in closure.roots)}", "functions:"]
    lines.extend(f"  {function.start:x} {function.name}" for function in closure.functions)
    lines.append("syscalls (per site, union of each register's resolved values):")
    sites: dict[tuple[str, int], dict[str, set[str]]] = {}
    for event in closure.syscalls:
        values = sites.setdefault((event.function, event.address), {name: set() for name in SYSCALL_REGISTERS})
        for name, value in event.registers:
            values[name].add(str(value))
    for (function, address), values in sites.items():
        rendered = " ".join(f"{name}={'|'.join(sorted(value))}" for name, value in values.items())
        lines.append(f"  {function}@{address:x} {rendered}")
    indirect = [f"  {function.name}@{instruction.address:x}: {instruction.text}"
                for function, instruction in closure.instructions() if instruction.indirect]
    if indirect:
        lines.append("indirect transfers (not followed):")
        lines.extend(indirect)
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "dump"):
        command = commands.add_parser(name)
        command.add_argument("elf", type=Path)
        command.add_argument("--root", action="append", required=True, help="closure root symbol (repeatable)")
        command.add_argument("--exclude", action="append", default=[],
                             help="do not enter this function (a separately qualified boundary)")
        command.add_argument("--follow-addresses", action="store_true",
                             help="also enter functions whose entry address is taken (callbacks, thread starts)")
        command.add_argument("--objdump", default="objdump")
        command.add_argument("--label", default="", help="prefix for failure messages")
    check_command = commands.choices["check"]
    check_command.add_argument("--syscall", action="append", default=[],
                               help="require a reachable syscall matching nr=N[,a1..a6|reg=VALUE] "
                                    "(VALUE: integer, arg:REG, &SYMBOL, or *)")
    check_command.add_argument("--no-syscall", action="append", default=[], help="forbid a matching syscall")
    check_command.add_argument("--every-syscall", action="append", default=[],
                               help="require every reachable syscall to match this constraint")
    check_command.add_argument("--syscalls-only", default="", help="comma-separated numbers every syscall must use")
    check_command.add_argument("--reaches", action="append", default=[], help="require a function in the closure")
    check_command.add_argument("--not-reaches", action="append", default=[], help="forbid a function in the closure")
    check_command.add_argument("--instruction", action="append", default=[],
                               help="require a closure instruction matching this regular expression")
    check_command.add_argument("--no-instruction", action="append", default=[],
                               help="forbid closure instructions matching this regular expression")
    arguments = parser.parse_args(argv)
    label = f"{arguments.label}: " if arguments.label else ""
    try:
        closure = closure_of(Candidate.from_elf(arguments.elf, arguments.objdump), arguments.root,
                             arguments.exclude, arguments.follow_addresses)
    except ClosureError as error:
        print(f"elf call closure: {label}{error}", file=sys.stderr)
        return 1
    if arguments.command == "dump":
        sys.stdout.write(describe(closure))
        return 0
    failures = check(closure, syscalls=arguments.syscall, no_syscalls=arguments.no_syscall,
                     every_syscall=arguments.every_syscall,
                     syscalls_only=[item for item in arguments.syscalls_only.split(",") if item],
                     reaches=arguments.reaches, not_reaches=arguments.not_reaches,
                     instructions=arguments.instruction, no_instructions=arguments.no_instruction)
    if failures:
        for failure in failures:
            print(f"elf call closure: {label}{'+'.join(arguments.root)}: {failure}", file=sys.stderr)
        sys.stderr.write(describe(closure))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
