#!/usr/bin/env python3
"""Verify that the M8 fenv probe uses direct AArch64 FPCR/FPSR access."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


FORBIDDEN_PUBLIC_SYMBOLS = (
    "feclearexcept",
    "feraiseexcept",
    "fetestexcept",
    "fegetround",
    "fesetround",
    "fegetenv",
    "fesetenv",
    "feholdexcept",
    "feupdateenv",
    "__errno_location",
    "malloc",
    "free",
)


class VerificationError(ValueError):
    """The fixture does not demonstrate the direct fenv contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm8_fenv_direct_probe.a"
    require(archive.is_file(), f"M8 fenv probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def has_undefined(symbols: str, name: str) -> bool:
    return bool(re.search(rf"^\s*U\s+{re.escape(name)}(?:@[^\s]+)?$", symbols, re.MULTILINE))


def inspect(readelf: str, disassembly: str, undefined_symbols: str = "") -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF binary")
    required_instructions = {
        "read_fpcr": r"\bmrs\s+(?:w|x)\d+,\s*fpcr\b",
        "read_fpsr": r"\bmrs\s+(?:w|x)\d+,\s*fpsr\b",
        "write_fpcr": r"\bmsr\s+fpcr,\s*(?:w|x)\d+\b",
        "write_fpsr": r"\bmsr\s+fpsr,\s*(?:w|x)\d+\b",
    }
    missing = tuple(
        name for name, pattern in required_instructions.items()
        if not re.search(pattern, disassembly, re.IGNORECASE)
    )
    require(not missing, "fixture is missing direct FPCR/FPSR instruction(s): " + ", ".join(missing))
    forbidden = tuple(
        name for name in FORBIDDEN_PUBLIC_SYMBOLS if has_undefined(undefined_symbols, name)
    )
    require(
        not forbidden,
        "fixture references forbidden public C ABI/TLS/mallocator symbol(s): " + ", ".join(forbidden),
    )
    return {
        "machine": "AArch64",
        "direct_fpcr_fpsr": True,
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
            tool_output((args.nm, "--undefined-only", str(archive))),
        )
        print(f"M8 direct fenv proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M8 direct fenv proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
