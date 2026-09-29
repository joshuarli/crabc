#!/usr/bin/env python3
"""Compare exact pow edge records and the finite powf identity correction."""
import struct
import sys
from collections import Counter
from pathlib import Path

oracle = Path(sys.argv[1]).read_bytes()
candidate = Path(sys.argv[2]).read_bytes()
expected_bytes = 2 * 20 * 20 * 4 * 5 * 8
if len(oracle) != expected_bytes or len(candidate) != expected_bytes:
    raise SystemExit(f"pow edge record size drifted: {len(oracle)}, {len(candidate)}")

corrected = 0
result_differences = 0
flag_differences = 0
rounding_modes = Counter()
outcomes = Counter()
for index, (old, new) in enumerate(zip(struct.iter_unpack('<5Q', oracle),
                                       struct.iter_unpack('<5Q', candidate))):
    if old[:2] != new[:2] or old[3] != new[3]:
        raise SystemExit(f"pow edge input or rounding changed at {index}: {old} / {new}")
    base, exponent, result, _, flags = new
    rounding_modes[new[3] & 0xffffffff] += 1
    for name, bit in (("invalid", 1), ("divide by zero", 4),
                      ("overflow", 8), ("underflow", 16), ("inexact", 32)):
        outcomes[name] += bool(flags & bit)
    magnitude = result & (0x7fffffff if base >> 32 == 1 else 0x7fffffffffffffff)
    outcomes["negative zero"] += magnitude == 0 and bool(
        result & (0x80000000 if base >> 32 == 1 else 0x8000000000000000))
    outcomes["subnormal result"] += (0 < magnitude <
        (0x00800000 if base >> 32 == 1 else 0x0010000000000000))
    if (base >> 32 == 1 and exponent == 0x3f800000
            and base & 0x7fffffff < 0x7f800000):
        if result != base & 0xffffffff or flags:
            raise SystemExit(f"powf finite identity failed at {index}: {old} / {new}")
        corrected += old != new
        result_differences += old[2] != new[2]
        flag_differences += old[4] != new[4]
    elif old != new:
        raise SystemExit(f"pow edge mismatch at {index}: {old} / {new}")
if rounding_modes != {0: 800, 0x400: 800, 0x800: 800, 0xc00: 800}:
    raise SystemExit(f"pow edge rounding coverage changed: {rounding_modes}")
if any(count == 0 for count in outcomes.values()) or len(outcomes) != 7:
    raise SystemExit(f"pow edge outcome coverage changed: {outcomes}")
if (corrected, result_differences, flag_differences) != (36, 12, 36):
    raise SystemExit("powf finite identity difference count changed: "
                     f"{corrected} records, {result_differences} results, "
                     f"{flag_differences} flags")
print(f"pow edge corpus: {expected_bytes // 40} records; "
      f"{expected_bytes // 40 - corrected} raw matches; "
      f"{corrected} explicit finite powf(x,1) differences "
      f"({result_differences} results, {flag_differences} flags); "
      "candidate identity and outcome coverage verified")
