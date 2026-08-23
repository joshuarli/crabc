#!/usr/bin/env python3
"""Verify the stateful-text probe remains off the public C text ABI."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


# The native surface must not fall back to C's mutable buffers, static tokenizer
# state, locale process state, allocator ownership, or TLS errno. Generic
# compiler memcpy/memset intrinsics are intentionally not included: a whole
# staticlib contains unrelated compiler lowering under those names and they do
# not establish a public C-ABI route from this facade.
FORBIDDEN_SYMBOLS = (
    "__xpg_basename",
    "basename",
    "dirname",
    "stpcpy",
    "stpncpy",
    "strcasestr",
    "strcat",
    "strcpy",
    "strdup",
    "strlcat",
    "strlcpy",
    "strncat",
    "strncpy",
    "strndup",
    "strsep",
    "strtok",
    "strtok_r",
    "strverscmp",
    "__errno_location",
    "malloc",
    "calloc",
    "realloc",
    "free",
)


class VerificationError(ValueError):
    """The archive does not demonstrate the native stateful-text contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libtext_stateful_direct_probe.a"
    require(archive.is_file(), f"stateful-text probe archive does not exist: {archive}")
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
        "crabc_rs_text_stateful_direct_probe" in defined_symbols,
        "fixture does not define the stateful-text probe entry point",
    )
    forbidden = tuple(name for name in FORBIDDEN_SYMBOLS if has_symbol(undefined_symbols, name))
    require(
        not forbidden,
        "fixture references forbidden public C text/allocator/errno symbol(s): "
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
        print(f"native stateful-text proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"native stateful-text proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
