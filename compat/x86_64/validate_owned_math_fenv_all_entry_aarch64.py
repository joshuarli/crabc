#!/usr/bin/env python3
"""Validate and compare the native arm64 math/fenv component stream."""
from pathlib import Path
import struct
import sys

import validate_libc_math_long_double_completion as completion

FRAME = struct.Struct('<IHHiII')
ROUNDING = struct.Struct('<6H4I16s')
RECORDS = {7: struct.Struct('<HHIII32s'), 8: struct.Struct('<HHIIi16s'),
           9: struct.Struct('<HHIII48s'), 10: struct.Struct('<HHIHHHHIiii32s16s')}
STAGES = ((1, 0), (2, 4 * 4 * 2 * 12 * 3 * ROUNDING.size),
          (3, 0), (4, 3408 * 40), (5, 1320 * 32),
          (6, 244 * completion.AARCH64_RECORD.size), (7, 2764 * 48),
          (8, 5544 * 32), (9, 7604 * 64), (10, 58984 * 80))


def read(path):
    data = Path(path).read_bytes()
    expected = sum(2 * FRAME.size + size for _, size in STAGES)
    if len(data) != expected:
        raise ValueError(f'{path}: stream has {len(data)} bytes, expected {expected}')
    offset = 0
    bodies = {}
    for stage, size in STAGES:
        for phase in (1, 2):
            frame = FRAME.unpack_from(data, offset)
            if frame != (0x4d464131, stage, phase, 0, 0x400000, 0x12):
                raise ValueError(f'{path}: invalid stage {stage} frame {phase}: {frame}')
            offset += FRAME.size
            if phase == 1:
                bodies[stage] = data[offset:offset + size]
                offset += size
    for ordinal, row in enumerate(ROUNDING.iter_unpack(bodies[2])):
        mode, remainder = divmod(ordinal, 4 * 2 * 12 * 3)
        seed, remainder = divmod(remainder, 2 * 12 * 3)
        operation, remainder = divmod(remainder, 12 * 3)
        index, precision = divmod(remainder, 3)
        rounding = (0, 0x800000, 0x400000, 0xc00000)[mode]
        exceptions = (0, 0x10, 0x2, 0x12)[seed]
        if not operation and index not in (0, 1, 8, 9):
            exceptions |= 0x10
        if (row[:6] != (precision, operation, mode, seed, index, 0)
                or row[6:8] != (rounding, exceptions)
                or row[8] & 0xc00000 != rounding or row[9] & 0x1f != exceptions):
            raise ValueError(f'{path}: invalid rounding record {ordinal}: {row[:-1]}')
    return bodies


def domain_flag_correction(oracle, reference, actual):
    if actual[0] != 1 or actual[4] != 1 or oracle[4] != 17 or reference[4] != 17:
        return False
    if actual[:4] != oracle[:4] or actual[5:] != oracle[5:] or reference != oracle:
        return False
    bits = int.from_bytes(actual[-1], 'little')
    magnitude = bits & ((1 << 127) - 1)
    return magnitude < (0x7fff << 112) and (bits >> 127 != 0 or magnitude < (0x3fff << 112))


def compare(oracle, reference, actual):
    matches = {'musl': 0, 'owned-helpers': 0, 'domain-flags': 0}
    for stage, _ in STAGES:
        if stage == 6:
            completion.compare_aarch64(list(completion.AARCH64_RECORD.iter_unpack(oracle[stage])),
                               list(completion.AARCH64_RECORD.iter_unpack(actual[stage])))
            if reference[stage] != actual[stage]:
                raise ValueError('binary128 completion differs from the owned-helper reference')
        elif stage in RECORDS:
            parser = RECORDS[stage]
            for ordinal, (musl, helper, candidate) in enumerate(zip(
                    parser.iter_unpack(oracle[stage]), parser.iter_unpack(reference[stage]),
                    parser.iter_unpack(actual[stage]))):
                if musl[:3] != helper[:3] or musl[:3] != candidate[:3]:
                    raise ValueError(f'stage {stage} record {ordinal} identity differs')
                if stage == 10 and (musl[-1] != helper[-1] or musl[-1] != candidate[-1]):
                    raise ValueError(f'stage {stage} record {ordinal} operand differs')
                protected = (stage == 7 and candidate[0] == 32) or (
                    stage == 10 and candidate[0] in (32, 44, 50, 51, 52))
                if protected and helper != musl:
                    raise ValueError(f'stage {stage} record {ordinal} corrected reference differs from musl')
                if candidate == musl:
                    matches['musl'] += 1
                elif not protected and candidate == helper:
                    matches['owned-helpers'] += 1
                elif not protected and stage == 10 and domain_flag_correction(musl, helper, candidate):
                    matches['domain-flags'] += 1
                else:
                    raise ValueError(f'stage {stage} record {ordinal} differs from both references: {candidate[:3]}')
        elif oracle[stage] != actual[stage] or oracle[stage] != reference[stage]:
            raise ValueError(f'stage {stage} differs from the pinned oracle')
    return matches


def main():
    if len(sys.argv) not in (2, 4):
        raise ValueError('usage: validator RECORDS [REFERENCE CANDIDATE]')
    oracle = read(sys.argv[1])
    if len(sys.argv) == 4:
        matches = compare(oracle, read(sys.argv[2]), read(sys.argv[3]))
        print(f'aarch64 math/fenv stream: PASS {matches}')
    else:
        print('aarch64 math/fenv stream: PASS')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print(f'aarch64 math/fenv stream: {error}', file=sys.stderr)
        raise SystemExit(1)
