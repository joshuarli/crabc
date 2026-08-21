#!/usr/bin/env python3
"""Verify M7 native thread code uses only the private singleton table."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


PRIVATE_RUNTIME = "__crabc_runtime_v1"
FORBIDDEN_PUBLIC_SYMBOLS = (
    "pthread_create",
    "pthread_join",
    "pthread_detach",
    "pthread_self",
    "pthread_cancel",
    "pthread_key_create",
    "pthread_key_delete",
    "pthread_getspecific",
    "pthread_setspecific",
    "__errno_location",
)


class VerificationError(ValueError):
    """The probe does not demonstrate the private-runtime contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fixture_archive(target_dir: Path) -> Path:
    archive = target_dir / "release" / "examples" / "libm7_runtime_thread_probe.a"
    require(archive.is_file(), f"M7 runtime-thread probe archive does not exist: {archive}")
    return archive


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def has_undefined(symbols: str, name: str) -> bool:
    return bool(re.search(rf"^\s*U\s+{re.escape(name)}(?:@[^\s]+)?$", symbols, re.MULTILINE))


def inspect(readelf: str, undefined_symbols: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF binary")
    require(
        has_undefined(undefined_symbols, PRIVATE_RUNTIME),
        "fixture does not reference the versioned private thread runtime",
    )
    forbidden = tuple(
        name for name in FORBIDDEN_PUBLIC_SYMBOLS if has_undefined(undefined_symbols, name)
    )
    require(
        not forbidden,
        "fixture references forbidden public C ABI/TLS errno symbol(s): " + ", ".join(forbidden),
    )
    return {
        "machine": "AArch64",
        "private_runtime": PRIVATE_RUNTIME,
        "forbidden_public_symbols": [],
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
        )
        print(f"M7 private thread runtime proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"M7 private thread runtime proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
