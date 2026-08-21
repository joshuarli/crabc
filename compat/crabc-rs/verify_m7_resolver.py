#!/usr/bin/env python3
"""Verify M7 native resolver code uses direct Linux DNS syscalls."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


REQUIRED_SYSCALLS = {
    73: "ppoll",
    198: "socket",
    203: "connect",
    206: "sendto",
    207: "recvfrom",
}
FORBIDDEN_PUBLIC_SYMBOLS = (
    "getaddrinfo",
    "getnameinfo",
    "gethostbyname",
    "gethostbyaddr",
    "res_query",
    "__res_state",
    "__errno_location",
)


class VerificationError(ValueError):
    """The probe does not demonstrate the direct-native resolver contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm7_resolver_direct_probe.a"
    require(archive.is_file(), f"M7 resolver probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def syscall_pattern(number: int) -> re.Pattern[str]:
    return re.compile(rf"mov\s+(?:w|x)8,\s*#{number:#x}\b[\s\S]{{0,900}}?\bsvc\b")


def inspect(readelf: str, disassembly: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF binary")
    require(re.search(r"\bsvc\b", disassembly), "fixture contains no direct AArch64 svc instruction")
    missing = tuple(
        name for number, name in REQUIRED_SYSCALLS.items() if not syscall_pattern(number).search(disassembly)
    )
    require(not missing, "fixture is missing direct Linux/AArch64 syscall(s): " + ", ".join(missing))
    forbidden = tuple(
        symbol
        for symbol in FORBIDDEN_PUBLIC_SYMBOLS
        if re.search(rf"<{re.escape(symbol)}(?:@[^>]*)?>", disassembly)
    )
    require(
        not forbidden,
        "fixture references forbidden public C ABI/TLS resolver symbol(s): " + ", ".join(forbidden),
    )
    return {
        "machine": "AArch64",
        "direct_svc": True,
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
        print(f"M7 direct resolver proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M7 direct resolver proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
