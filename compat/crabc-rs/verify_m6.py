#!/usr/bin/env python3
"""Verify that the M6 signal/process probe stays off crabc's C ABI."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


FORBIDDEN_PUBLIC_SYMBOLS = (
    "fork", "execve", "wait", "waitpid", "waitid", "kill", "tgkill",
    "sigaction", "sigprocmask", "sigpending", "sigsuspend", "sigtimedwait",
    "sigaltstack", "sigqueue", "__errno_location",
)
REQUIRED_SYSCALLS = {
    74: "signalfd4", 94: "exit_group", 95: "waitid", 129: "kill", 131: "tgkill",
    132: "sigaltstack", 133: "rt_sigsuspend", 134: "rt_sigaction",
    135: "rt_sigprocmask", 136: "rt_sigpending", 137: "rt_sigtimedwait",
    138: "rt_sigqueueinfo", 139: "rt_sigreturn", 220: "clone", 221: "execve",
    260: "wait4",
}


class VerificationError(ValueError):
    """The fixture does not demonstrate the M6 direct-operation contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm6_direct_probe.a"
    require(archive.is_file(), f"M6 direct probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def syscall_pattern(number: int) -> re.Pattern[str]:
    return re.compile(rf"mov\s+(?:w|x)8,\s+#{number:#x}\b[\s\S]{{0,900}}?\bsvc\b")


def inspect(readelf: str, disassembly: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF binary")
    require(re.search(r"\bsvc\b", disassembly), "fixture contains no direct AArch64 svc instruction")
    missing = tuple(name for number, name in REQUIRED_SYSCALLS.items() if not syscall_pattern(number).search(disassembly))
    require(not missing, "fixture is missing direct Linux/AArch64 syscall(s): " + ", ".join(missing))
    forbidden = tuple(
        symbol for symbol in FORBIDDEN_PUBLIC_SYMBOLS
        if re.search(rf"<{re.escape(symbol)}(?:@[^>]*)?>", disassembly)
    )
    require(not forbidden, "fixture references forbidden public C ABI/TLS errno symbol(s): " + ", ".join(forbidden))
    return {
        "machine": "AArch64", "direct_svc": True,
        "direct_syscalls": list(REQUIRED_SYSCALLS.values()),
        "forbidden_public_symbols": [],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=Path("target"))
    parser.add_argument("--readelf", default="llvm-readelf")
    parser.add_argument("--objdump", default="llvm-objdump")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        archive = fixture_archive(args.target_dir)
        report = inspect(
            tool_output((args.readelf, "--file-header", str(archive))),
            tool_output((args.objdump, "--disassemble", "--demangle", str(archive))),
        )
        print(f"M6 direct syscall proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M6 direct syscall proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
