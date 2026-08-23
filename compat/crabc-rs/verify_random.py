#!/usr/bin/env python3
"""Verify that the random-state probe uses direct Linux entropy."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


FORBIDDEN_PUBLIC_SYMBOLS = (
    "drand48", "erand48", "getrandom", "jrand48", "lcong48", "lrand48",
    "mrand48", "nrand48", "rand", "rand_r", "random", "seed48", "srand",
    "srand48", "srandom", "initstate", "setstate", "__errno_location",
)
GETRANDOM_SYSCALL = 278


class VerificationError(ValueError):
    """The fixture does not demonstrate the direct-native random contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "librandom_direct_probe.a"
    require(archive.is_file(), f"random probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def syscall_pattern(number: int) -> re.Pattern[str]:
    return re.compile(rf"mov\s+w8,\s+#{number:#x}\b[\s\S]{{0,900}}?\bsvc\b")


def inspect(readelf: str, disassembly: str, defined_symbols: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF archive member")
    require(
        "crabc_rs_random_direct_probe" in defined_symbols,
        "fixture does not define the random probe entry point",
    )
    require(syscall_pattern(GETRANDOM_SYSCALL).search(disassembly), "fixture lacks direct getrandom syscall")
    forbidden = tuple(
        symbol
        for symbol in FORBIDDEN_PUBLIC_SYMBOLS
        if re.search(rf"<{re.escape(symbol)}(?:@[^>]*)?>", disassembly)
    )
    require(
        not forbidden,
        "fixture references forbidden C random/errno symbol(s): " + ", ".join(forbidden),
    )
    return {
        "machine": "AArch64",
        "direct_svc": True,
        "direct_syscalls": ["getrandom"],
        "forbidden_public_symbols": [],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=Path("target"))
    parser.add_argument("--readelf", default="llvm-readelf")
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--nm", default="llvm-nm")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        archive = fixture_archive(args.target_dir)
        report = inspect(
            tool_output((args.readelf, "--file-header", str(archive))),
            tool_output((args.objdump, "--disassemble", "--demangle", str(archive))),
            tool_output((args.nm, "--defined-only", str(archive))),
        )
        print(f"native random proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"native random proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
