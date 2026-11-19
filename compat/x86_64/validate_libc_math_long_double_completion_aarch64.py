#!/usr/bin/env python3
"""Compare native binary128 records against the musl oracle."""
import struct
import sys
from pathlib import Path

RECORD = struct.Struct("<HHIIIQQ16s")
MODES = (0, 0x800000, 0x400000, 0xc00000)


def read(path):
    data = Path(path).read_bytes()
    if len(data) != RECORD.size * 244:
        raise ValueError(f"{path}: expected 244 complete records")
    return list(RECORD.iter_unpack(data))


def compare(reference, candidate):
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
                if oracle[5:7] != actual[5:7]:
                    raise ValueError(f"FPCR differs: {function}/{index}/{mode}")
                if oracle[3:5] != actual[3:5]:
                    raise ValueError(f"FPSR differs: {function}/{index}/{mode}")
                if oracle[7] != actual[7]:
                    raise ValueError(f"binary128 value differs: {function}/{index}/{mode}")
    return 0


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("usage: validator ORACLE CANDIDATE")
        compare(read(sys.argv[1]), read(sys.argv[2]))
        print("aarch64 binary128: PASS (244 records, zero differences)")
    except (OSError, ValueError) as error:
        print(f"aarch64 binary128: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
