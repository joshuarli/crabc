#!/usr/bin/env python3
"""Validate and compare ARM long-double completion records."""
import sys
from pathlib import Path
from validate_libc_math_long_double_completion import read_aarch64, compare_aarch64

if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("usage: validator ORACLE CANDIDATE")
        compare_aarch64(read_aarch64(Path(sys.argv[1])), read_aarch64(Path(sys.argv[2])))
        print("aarch64 binary128: PASS (244 records)")
    except (OSError, ValueError) as error:
        print(f"aarch64 binary128: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
