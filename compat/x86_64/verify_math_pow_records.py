#!/usr/bin/env python3
"""Compare the fixed pow corpus, accounting for finite exponent-one corrections."""
import struct
import sys
from pathlib import Path

reference = Path(sys.argv[1]).read_bytes()
candidate = Path(sys.argv[2]).read_bytes()
if len(reference) != 256 * 40 or len(candidate) != len(reference):
    raise SystemExit('pow record count drifted')
corrected = 0
for index, (old, new) in enumerate(zip(struct.iter_unpack('<5Q', reference), struct.iter_unpack('<5Q', candidate))):
    if old[:2] != new[:2] or old[3] != new[3]:
        raise SystemExit(f'pow input/rounding mismatch at record {index}')
    base, exponent, result, modes, flags = new
    if base >> 32 == 1 and exponent == 0x3f800000 and base & 0x7fffffff < 0x7f800000:
        if result != base & 0xffffffff or flags:
            raise SystemExit(f'powf finite identity is not exact at record {index}')
        corrected += old != new
    elif base >> 32 != 1 and exponent == 0x3ff0000000000000 and base & 0x7fffffffffffffff < 0x7ff0000000000000:
        if result != base or flags:
            raise SystemExit(f'pow finite identity is not exact at record {index}')
        corrected += old != new
    elif old != new:
        raise SystemExit(f'uncorrected pow record differs at record {index}')
print(f'pow corpus: 256 records; {corrected} finite exponent-one identity differences; raw oracle retained')
