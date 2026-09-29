#!/usr/bin/env python3
"""Compare pow/powf result bits and fenv against pinned musl in every mode."""
import struct
import sys
from collections import Counter
from pathlib import Path


huge = len(sys.argv) == 4 and sys.argv[3] == "--huge"
if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and not huge):
    raise SystemExit("usage: verify_math_pow_edges.py oracle candidate [--huge]")
oracle = Path(sys.argv[1]).read_bytes()
candidate = Path(sys.argv[2]).read_bytes()
record_size = struct.calcsize("<5Q")
if len(oracle) != len(candidate) or not oracle or len(oracle) % record_size:
    raise SystemExit(f"pow edge record size differs: {len(oracle)}, {len(candidate)}")

huge_exponents = {
    64: {0x432ffffffffffffe, 0x432fffffffffffff, 0x4330000000000000,
         0x4330000000000001, 0x433fffffffffffff, 0x4340000000000000,
         0xc32ffffffffffffe, 0xc32fffffffffffff, 0xc330000000000000,
         0xc330000000000001, 0xc340000000000000},
    32: {0x4afffffe, 0x4affffff, 0x4b000000, 0x4b000001,
         0x4b7fffff, 0x4b800000, 0xcafffffe, 0xcaffffff,
         0xcb000000, 0xcb000001, 0xcb800000},
}
nonintegral_huge_exponents = {
    64: {0x432fffffffffffff, 0xc32fffffffffffff},
    32: {0x4affffff, 0xcaffffff},
}

coverage = Counter()
mode_rows = Counter()
corrected = Counter()
for index, (old, new) in enumerate(zip(struct.iter_unpack("<5Q", oracle),
                                       struct.iter_unpack("<5Q", candidate))):
    if old[:2] != new[:2] or old[3] != new[3]:
        raise SystemExit(f"pow edge input or rounding changed at {index}: {old} / {new}")
    base, exponent, result, modes, packed_status = new
    flags = packed_status & 0xffffffff
    if old[4] >> 32 != 0x5a5 or packed_status >> 32 != 0x5a5:
        raise SystemExit(f"pow changed caller errno at record {index}: {old} / {new}")
    precision = "powf" if base >> 32 == 1 else "pow"
    bits = 32 if precision == "powf" else 64
    sign = 1 << (bits - 1)
    exponent_mask = 0x7f800000 if bits == 32 else 0x7ff0000000000000
    fraction_mask = 0x007fffff if bits == 32 else 0x000fffffffffffff
    quiet_bit = fraction_mask ^ (fraction_mask >> 1)
    positive_odd, negative_odd, positive_even, negative_even = (
        (0x4008000000000000, 0xc008000000000000,
         0x4000000000000000, 0xc000000000000000) if bits == 64 else
        (0x40400000, 0xc0400000, 0x40000000, 0xc0000000)
    )
    base &= (1 << bits) - 1
    magnitude = result & (sign - 1)
    requested, observed = modes >> 32, modes & 0xffffffff
    if requested != observed:
        raise SystemExit(f"pow changed rounding mode at record {index}")
    mode_rows[precision, requested] += 1
    coverage[precision, requested, "base subnormal"] += 0 < (base & (sign - 1)) < fraction_mask + 1
    coverage[precision, requested, "exponent subnormal"] += 0 < (exponent & (sign - 1)) < fraction_mask + 1
    coverage[precision, requested, "quiet NaN input"] += (
        (base & exponent_mask) == exponent_mask and bool(base & quiet_bit)
    )
    coverage[precision, requested, "signaling NaN input"] += (
        (base & exponent_mask) == exponent_mask and bool(base & fraction_mask)
        and not bool(base & quiet_bit)
    )
    coverage[precision, requested, "quiet NaN exponent"] += (
        (exponent & exponent_mask) == exponent_mask and bool(exponent & quiet_bit)
    )
    coverage[precision, requested, "signaling NaN exponent"] += (
        (exponent & exponent_mask) == exponent_mask and bool(exponent & fraction_mask)
        and not bool(exponent & quiet_bit)
    )
    coverage[precision, requested, "negative base, positive odd exponent"] += bool(base & sign) and exponent == positive_odd
    coverage[precision, requested, "negative base, negative odd exponent"] += bool(base & sign) and exponent == negative_odd
    coverage[precision, requested, "negative base, positive even exponent"] += bool(base & sign) and exponent == positive_even
    coverage[precision, requested, "negative base, negative even exponent"] += bool(base & sign) and exponent == negative_even
    coverage[precision, requested, "negative zero"] += magnitude == 0 and bool(result & sign)
    coverage[precision, requested, "subnormal result"] += 0 < magnitude < fraction_mask + 1
    coverage[precision, requested, "negative base, huge exponent"] += bool(base & sign) and exponent in huge_exponents[bits]
    coverage[precision, requested, "huge nonintegral exponent"] += exponent in nonintegral_huge_exponents[bits]
    for name, bit in (("invalid", 1), ("divide by zero", 4),
                      ("overflow", 8), ("underflow", 16), ("inexact", 32)):
        coverage[precision, requested, name] += bool(flags & bit)
    if (precision == "powf" and exponent == 0x3f800000
            and base & 0x7fffffff < 0x7f800000):
        if result != base or flags:
            raise SystemExit(f"powf finite identity failed at {index}: {old} / {new}")
        corrected["records"] += old != new
        corrected["results"] += old[2] != new[2]
        corrected["flags"] += old[4] != new[4]
    elif old != new:
        raise SystemExit(f"pow edge mismatch at {index}: {old} / {new}")

expected_modes = {0, 0x400, 0x800, 0xc00}
expected_coverage = {
    "base subnormal", "exponent subnormal", "quiet NaN input",
    "signaling NaN input", "quiet NaN exponent", "signaling NaN exponent",
    "negative base, positive odd exponent", "negative base, negative odd exponent",
    "negative base, positive even exponent", "negative base, negative even exponent",
    "negative zero", "subnormal result", "invalid", "divide by zero",
    "overflow", "underflow", "inexact",
}
if huge:
    expected_coverage -= {
        "exponent subnormal", "signaling NaN input", "quiet NaN exponent",
        "signaling NaN exponent",
    }
    expected_coverage |= {"negative base, huge exponent", "huge nonintegral exponent"}
for precision in ("pow", "powf"):
    rows = {mode: count for (kind, mode), count in mode_rows.items() if kind == precision}
    if set(rows) != expected_modes or len(set(rows.values())) != 1:
        raise SystemExit(f"{precision} rounding coverage changed: {rows}")
    for mode in expected_modes:
        exercised = {name for (kind, tested_mode, name), count in coverage.items()
                     if kind == precision and tested_mode == mode and count > 0}
        if exercised != expected_coverage:
            raise SystemExit(f"{precision} edge coverage changed in mode {mode:#x}: "
                             f"missing {expected_coverage - exercised}; "
                             f"unexpected {exercised - expected_coverage}")
if corrected["records"] == 0:
    raise SystemExit("powf finite identity correction was not exercised")
print(f"pow {'huge-exponent' if huge else 'edge'} corpus: {len(oracle) // record_size} records; "
      f"{corrected['records']} explicit finite powf(x,1) differences "
      f"({corrected['results']} results, {corrected['flags']} flags); "
      "all rounding modes, values, caller errno, and IEEE flag classes verified")
