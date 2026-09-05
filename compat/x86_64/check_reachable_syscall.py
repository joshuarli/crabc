#!/usr/bin/env python3
"""Prove a selected x86 C wrapper reaches its exact Linux syscall instruction.

Rust may outline the private ``raw_syscall::syscallN`` leaf when this static
archive is built without LTO. A C export then loads its named syscall number
into the first C argument register and transfers directly to that leaf. This
checker verifies that concrete path instead of requiring incidental inlining,
while rejecting an unrelated immediate or syscall instruction elsewhere in the
candidate.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class SyscallProofError(RuntimeError):
    """The selected wrapper has no exact machine-code syscall path."""


@dataclass(frozen=True)
class SyscallProof:
    """The checked wrapper-to-syscall instruction path."""

    path: str
    helper: str | None


_INSTRUCTION = re.compile(
    r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+(?P<text>\S.*)$"
)
_DIRECT_TRANSFER = re.compile(
    r"^(?:call|jmp)(?:q|l)?\s+(?:0x)?[0-9a-fA-F]+\s+<(?P<target>[^>]+)>$"
)


def _instructions(disassembly: str) -> list[str]:
    result: list[str] = []
    for line in disassembly.splitlines():
        match = _INSTRUCTION.match(line)
        if match is not None:
            result.append(" ".join(match.group("text").split()))
    return result


def _normalized_word(value: str) -> str:
    try:
        number = int(value, 16)
    except ValueError as error:
        raise SyscallProofError(f"invalid x86 syscall word: {value}") from error
    if number < 0:
        raise SyscallProofError(f"invalid negative x86 syscall word: {value}")
    return f"{number:x}"


def _is_number_load(instruction: str, word: str, register: str) -> bool:
    return re.fullmatch(
        rf"mov[a-z]* \$0x0*{re.escape(word)},%{register}", instruction.lower()
    ) is not None


def _writes_rdi(instruction: str) -> bool:
    operation = instruction.split(maxsplit=1)[0]
    if operation.startswith(("cmp", "test")):
        return False
    return re.search(r",%(?:r|e)di$", instruction.lower()) is not None


def _outlined_target(
    symbol: str, word: str, arity: int, instructions: list[str]
) -> str | None:
    loaded = False
    expected_helper = f"raw_syscall8syscall{arity}"
    for instruction in instructions:
        if not loaded:
            if _is_number_load(instruction, word, "edi"):
                loaded = True
            continue
        transfer = _DIRECT_TRANSFER.fullmatch(instruction)
        if transfer is not None:
            target = transfer.group("target")
            if expected_helper not in target:
                raise SyscallProofError(
                    f"{symbol} transfers after syscall load to an unrelated target: {target}"
                )
            return target
        if _writes_rdi(instruction):
            raise SyscallProofError(
                f"{symbol} overwrites its named syscall word before reaching raw_syscall"
            )
    return None


def _prove_direct(symbol: str, word: str, instructions: list[str]) -> bool:
    meaningful = [
        instruction
        for instruction in instructions
        if not instruction.startswith(("nop", "endbr"))
    ]
    if len(meaningful) != 3:
        return False
    if not _is_number_load(meaningful[0], word, "eax"):
        return False
    if meaningful[1] != "syscall":
        return False
    if meaningful[2] not in {"ret", "retq"}:
        return False
    del symbol
    return True


def _prove_helper(symbol: str, helper: str, arity: int, instructions: list[str]) -> None:
    expected_moves = {
        0: ("mov %rdi,%rax",),
        1: ("mov %rdi,%rax", "mov %rsi,%rdi"),
        2: ("mov %rdi,%rax", "mov %rsi,%rdi", "mov %rdx,%rsi"),
        3: ("mov %rdi,%rax", "mov %rsi,%rdi", "mov %rdx,%rsi", "mov %rcx,%rdx"),
        4: ("mov %rdi,%rax", "mov %rsi,%rdi", "mov %rdx,%rsi", "mov %rcx,%rdx", "mov %r8,%r10"),
        5: ("mov %rdi,%rax", "mov %rsi,%rdi", "mov %rdx,%rsi", "mov %rcx,%rdx", "mov %r8,%r10", "mov %r9,%r8"),
        6: ("mov %r9,%r11", "mov %rdi,%rax", "mov 0x8(%rsp),%r9", "mov %rsi,%rdi", "mov %rdx,%rsi", "mov %rcx,%rdx", "mov %r8,%r10", "mov %r11,%r8"),
    }[arity]
    meaningful = [
        instruction.lower()
        for instruction in instructions
        if not instruction.startswith(("nop", "endbr"))
    ]
    if len(meaningful) != len(expected_moves) + 2:
        raise SyscallProofError(
            f"{symbol} helper {helper} is not the exact raw syscall return leaf"
        )
    if tuple(meaningful[: len(expected_moves)]) != expected_moves:
        detail = (
            "does not move rdi into rax immediately before its syscall"
            if meaningful[0:1] != ["mov %rdi,%rax"]
            else "does not transfer Linux syscall arguments through exact x86 registers"
        )
        raise SyscallProofError(f"{symbol} helper {helper} {detail}")
    if meaningful[-2] != "syscall" or meaningful[-1] not in {"ret", "retq"}:
        raise SyscallProofError(
            f"{symbol} helper {helper} is not the exact raw syscall return leaf"
        )


def prove_disassemblies(
    symbol: str,
    syscall_word: str,
    arity: int,
    symbol_disassembly: str,
    helper_disassembly: str,
) -> SyscallProof:
    """Check direct code or the exact outlined raw-syscall helper path."""
    if arity < 0 or arity > 6:
        raise SyscallProofError(f"{symbol} has invalid syscall arity {arity}")
    word = _normalized_word(syscall_word)
    wrapper = _instructions(symbol_disassembly)
    if _prove_direct(symbol, word, wrapper):
        return SyscallProof(path="direct", helper=None)
    helper = _outlined_target(symbol, word, arity, wrapper)
    if helper is None:
        raise SyscallProofError(
            f"{symbol} has no direct syscall path or transfer to raw_syscall{arity}"
        )
    _prove_helper(symbol, helper, arity, _instructions(helper_disassembly))
    return SyscallProof(path="outlined", helper=helper)


def disassemble(objdump: str, candidate: Path, symbol: str) -> str:
    process = subprocess.run(
        [objdump, "-d", f"--disassemble={symbol}", str(candidate)],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise SyscallProofError(
            f"objdump could not disassemble {symbol}: {process.stderr.strip()}"
        )
    return process.stdout


def prove_candidate(
    objdump: str, candidate: Path, symbol: str, syscall_word: str, arity: int
) -> SyscallProof:
    """Disassemble one final candidate wrapper and its selected helper."""
    wrapper = disassemble(objdump, candidate, symbol)
    word = _normalized_word(syscall_word)
    if _prove_direct(symbol, word, _instructions(wrapper)):
        return SyscallProof(path="direct", helper=None)
    helper = _outlined_target(symbol, word, arity, _instructions(wrapper))
    if helper is None:
        raise SyscallProofError(
            f"{symbol} has no direct syscall path or transfer to raw_syscall{arity}"
        )
    proof = prove_disassemblies(
        symbol,
        syscall_word,
        arity,
        wrapper,
        disassemble(objdump, candidate, helper),
    )
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objdump", required=True)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--symbol", required=True)
    parser.add_argument("--syscall", required=True)
    parser.add_argument("--arity", required=True, type=int)
    arguments = parser.parse_args()
    proof = prove_candidate(
        arguments.objdump,
        arguments.candidate,
        arguments.symbol,
        arguments.syscall,
        arguments.arity,
    )
    print(
        f"x86 reachable syscall: {arguments.symbol}=0x{_normalized_word(arguments.syscall)} "
        f"({proof.path}" + (f" via {proof.helper}" if proof.helper else "") + ")"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyscallProofError as error:
        raise SystemExit(f"x86 reachable syscall: ERROR: {error}") from error
