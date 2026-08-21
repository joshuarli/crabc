#!/usr/bin/env python3
"""Verify the M7 native synchronization probe uses only direct futex syscalls."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


class VerificationError(ValueError):
    """The probe does not demonstrate the M7 direct-native contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm7_sync_direct_probe.a"
    require(archive.is_file(), f"M7 synchronization probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def inspect(readelf: str, disassembly: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF binary")
    require(re.search(r"\bsvc\b", disassembly), "fixture contains no direct AArch64 svc instruction")
    require(
        re.search(r"mov\s+(?:w|x)8,\s*#0x62\b[\s\S]{0,900}?\bsvc\b", disassembly),
        "fixture contains no direct AArch64 futex syscall (98)",
    )
    forbidden = tuple(
        symbol
        for symbol in ("pthread_", "__errno_location", "std::sync")
        if symbol in disassembly
    )
    require(not forbidden, "fixture references forbidden C/runtime symbol(s): " + ", ".join(forbidden))
    return {
        "machine": "AArch64",
        "direct_svc": True,
        "direct_syscalls": ["futex"],
        "forbidden_symbols": [],
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
        print(f"M7 direct futex proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M7 direct futex proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
