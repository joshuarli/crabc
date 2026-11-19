#!/usr/bin/env python3
"""Compare native binary128 records, including the selected helper differences."""
import struct
import sys
from pathlib import Path

RECORD = struct.Struct("<HHIIIQQ16s")
MODES = (0, 0x800000, 0x400000, 0xc00000)
FLAG_DIFFERENCES = {1: {11: 16, 12: 20}, 2: {2: 24, 3: 24, 8: 16, 9: 16, 10: 16, 11: 16, 23: 1}}
FLAG_DIFFERENCES[3] = FLAG_DIFFERENCES[2]
ROUNDING_DIFFERENCES = {1: {11, 12}, 2: {2, 3, 8, 9, 10, 11}, 3: {2, 3, 8, 9, 10, 11}}


def read(path):
    data = Path(path).read_bytes()
    if len(data) != RECORD.size * 244:
        raise ValueError(f"{path}: expected 244 complete records")
    return list(RECORD.iter_unpack(data))


def compare(reference, candidate):
    nearest = {}
    discrepancies = 0
    cursor = 0
    for mode in MODES:
        for function, count in ((1, 13), (2, 24), (3, 24)):
            for index in range(count):
                oracle, actual = reference[cursor], candidate[cursor]
                cursor += 1
                for record in (oracle, actual):
                    if (record[:3] != (function, index, mode) or record[5] != record[6]
                            or record[5] & 0xc00000 != mode):
                        raise ValueError(f"invalid identity or FPCR: {function}/{index}/{mode}")
                    if record[3] & 0x1f != record[4]:
                        raise ValueError(f"FPSR and fenv disagree: {function}/{index}/{mode}")
                if mode == 0:
                    nearest[function, index] = oracle[7]
                if oracle[5:7] != actual[5:7]:
                    raise ValueError(f"FPCR differs: {function}/{index}/{mode}")
                expected_value = (nearest[function, index]
                    if index in ROUNDING_DIFFERENCES[function] else oracle[7])
                expected_flags = FLAG_DIFFERENCES[function].get(index)
                if expected_flags is None:
                    if oracle[3:5] != actual[3:5]:
                        raise ValueError(f"unexpected FPSR difference: {function}/{index}/{mode}")
                elif oracle[3:5] != (expected_flags, expected_flags) or actual[3:5] != (0, 0):
                    raise ValueError(f"known helper flags changed: {function}/{index}/{mode}")
                if actual[7] != expected_value:
                    raise ValueError(f"binary128 value differs: {function}/{index}/{mode}")
                discrepancies += oracle[3:5] != actual[3:5] or oracle[7] != actual[7]
    return discrepancies


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("usage: validator ORACLE CANDIDATE")
        differences = compare(read(sys.argv[1]), read(sys.argv[2]))
        print(f"aarch64 binary128: PASS (244 records, {differences} known helper differences)")
    except (OSError, ValueError) as error:
        print(f"aarch64 binary128: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
