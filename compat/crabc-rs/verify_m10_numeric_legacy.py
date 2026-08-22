#!/usr/bin/env python3
"""Verify that the M10 legacy-numeric probe stays off the C callback ABI."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


FORBIDDEN_SYMBOLS = (
    "a64l", "l64a", "bsearch", "lfind", "lsearch", "qsort_r",
    "malloc", "calloc", "realloc", "free", "malloc_usable_size", "__errno_location",
)


class VerificationError(ValueError):
    """The fixture does not demonstrate the direct-native numeric contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm10_numeric_legacy_direct_probe.a"
    require(archive.is_file(), f"M10 legacy-numeric probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def has_symbol(symbols: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}(?:@[^\s]+)?\b", symbols))


def inspect(readelf: str, undefined_symbols: str, defined_symbols: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF archive member")
    require(
        "crabc_rs_m10_numeric_legacy_direct_probe" in defined_symbols,
        "fixture does not define the M10 legacy-numeric probe entry point",
    )
    forbidden = tuple(name for name in FORBIDDEN_SYMBOLS if has_symbol(undefined_symbols, name))
    require(
        not forbidden,
        "fixture references forbidden C legacy-numeric/allocator/errno symbol(s): "
        + ", ".join(forbidden),
    )
    return {
        "machine": "AArch64",
        "direct_native": True,
        "forbidden_symbols": [],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=Path("target"))
    parser.add_argument("--readelf", default="llvm-readelf")
    parser.add_argument("--nm", default="llvm-nm")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        archive = fixture_archive(args.target_dir)
        report = inspect(
            tool_output((args.readelf, "--file-header", str(archive))),
            tool_output((args.nm, "--undefined-only", str(archive))),
            tool_output((args.nm, "--defined-only", str(archive))),
        )
        print(f"M10 native legacy-numeric proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M10 native legacy-numeric proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
