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

INVALID, OVERFLOW, UNDERFLOW, INEXACT = 1, 4, 8, 16
SIGN = 1 << 127
MAGNITUDE = SIGN - 1
FRACTION = (1 << 112) - 1
QUIET = 1 << 111
INFINITY = 0x7fff << 112
ONE = 0x3fff << 112
BINARY64_MAX = (0x43fe << 112) | (((1 << 52) - 1) << 60)
BINARY64_MIN = 0x3c01 << 112
ACOSHL, CPOWL = 1, 185
LONG_DOUBLE, LONG_DOUBLE_PAIR = 3, 9
# The l_values operands of libc_math_elementary_long_double_probe.c, by case index.
ELEMENTARY_OPERANDS = (
    SIGN | INFINITY, SIGN | (0x7ffe << 112) | FRACTION, 0xc002 << 112, 0xc000 << 112,
    0xbfff8 << 108, 0xbfff << 112, 0xbffe << 112, SIGN | 1, SIGN, 0, 1, 1 << 112,
    0x3ffd << 112, 0x3ffe << 112, ONE, 0x3fff8 << 108, 0x4000 << 112, 0x4002 << 112,
    (0x7ffe << 112) | FRACTION, INFINITY, INFINITY | QUIET | 0x1234)
# Boundary cpowl cases of libc_math_abi_boundary_probe.c whose complex product
# has two NaN factors: l_complex rows 0, 1, 4, 5 and 6 as z (through clogl) and
# rows 4 and 5 as c.
CPOWL_NAN_PRODUCT_CASES = frozenset((0x000, 0x001, 0x004, 0x005, 0x006, 0x104, 0x105))


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


def is_nan(bits):
    return bits & MAGNITUDE > INFINITY


def narrowing_exceptions(bits):
    magnitude = bits & MAGNITUDE
    exponent = magnitude >> 112
    if magnitude == 0 or exponent == 0x7fff:
        return 0
    significand = (magnitude & FRACTION) | ((exponent != 0) << 112)
    trailing = (significand & -significand).bit_length() - 1
    scale = max(exponent, 1) - 0x3fff - 112 + trailing
    if magnitude <= BINARY64_MAX and significand >> trailing < 1 << 53 and scale >= -1074:
        return 0
    return (INEXACT | (OVERFLOW if magnitude > BINARY64_MAX else 0)
            | (UNDERFLOW if magnitude < BINARY64_MIN else 0))


def acoshl_domain_flags(stage, musl, reference, candidate):
    if stage == 7 and candidate[4] == 1 and candidate[1] < len(ELEMENTARY_OPERANDS):
        operand, flags, value = ELEMENTARY_OPERANDS[candidate[1]], 3, 5
    elif stage == 10 and candidate[6] == LONG_DOUBLE:
        operand, flags, value = int.from_bytes(candidate[12], 'little'), 4, 11
    else:
        return False
    if candidate[0] != ACOSHL or reference != musl or is_nan(operand):
        return False
    if operand & SIGN == 0 and operand >= ONE:
        return False
    if any(index != flags and musl[index] != candidate[index] for index in range(len(musl))):
        return False
    permitted = INVALID | narrowing_exceptions(operand)
    return (is_nan(int.from_bytes(candidate[value][:16], 'little')) and candidate[flags] == INVALID
            and musl[flags] & INVALID != 0 and musl[flags] & ~permitted == 0)


def cpowl_nan_propagation(stage, musl, reference, candidate):
    if (stage != 10 or candidate[0] != CPOWL or candidate[6] != LONG_DOUBLE_PAIR
            or candidate[1] not in CPOWL_NAN_PRODUCT_CASES or reference != candidate):
        return False
    if musl[:11] != candidate[:11] or musl[12] != candidate[12]:
        return False
    for offset in (0, 16):
        expected, actual = (int.from_bytes(record[11][offset:offset + 16], 'little')
                            for record in (musl, candidate))
        if expected != actual and not all(is_nan(bits) and bits & QUIET for bits in (expected, actual)):
            return False
    return True


CONTRACTS = (('acoshl-domain-flags', acoshl_domain_flags),
             ('cpowl-nan-propagation', cpowl_nan_propagation))


def compare(oracle, reference, actual):
    matches = dict.fromkeys(('musl', *(name for name, _ in CONTRACTS)), 0)
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
                    continue
                name = next((name for name, contract in CONTRACTS
                             if contract(stage, musl, helper, candidate)), None)
                if name is None:
                    raise ValueError(f'stage {stage} record {ordinal} differs from pinned musl '
                                     f'outside every difference contract: {candidate[:3]}')
                matches[name] += 1
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
