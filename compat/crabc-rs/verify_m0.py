#!/usr/bin/env python3
"""Verify that the M0 native fixture stays off crabc's public C ABI.

The caller builds the no-std ``m0_direct_probe`` static library for native
Linux/AArch64 and then points this checker at the target directory. Its archive
must contain the AArch64 direct-syscall instruction and must not contain a call
to the public libc entry points or TLS errno accessor that the native slice is
forbidden to use.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


FORBIDDEN_PUBLIC_SYMBOLS = ("openat", "read", "write", "close", "__errno_location")


class VerificationError(ValueError):
    """The fixture does not demonstrate the M0 direct-operation contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm0_direct_probe.a"
    require(archive.is_file(), f"M0 direct probe archive does not exist: {archive}")
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

    forbidden = tuple(
        symbol
        for symbol in FORBIDDEN_PUBLIC_SYMBOLS
        if re.search(rf"<{re.escape(symbol)}(?:@[^>]*)?>", disassembly)
    )
    require(
        not forbidden,
        "fixture references forbidden public C ABI/TLS errno symbol(s): " + ", ".join(forbidden),
    )
    return {
        "machine": "AArch64",
        "direct_svc": True,
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
        readelf = tool_output((args.readelf, "--file-header", str(archive)))
        disassembly = tool_output((args.objdump, "--disassemble", "--demangle", str(archive)))
        report = inspect(readelf, disassembly)
        print(f"M0 direct syscall proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M0 direct syscall proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
