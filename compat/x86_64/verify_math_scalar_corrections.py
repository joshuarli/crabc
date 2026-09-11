#!/usr/bin/env python3
"""Test scalar conformance with exact integer dyadics, never host libm arithmetic.

The checker specifies single rounding of exact x*y+z, not the implementation's
binary64 or dd intermediate algorithm. The pinned musl arm remains a separate
process and its mismatches are reported, never relabelled as successful tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import subprocess
from pathlib import Path

MODES = (0, 0x400, 0x800, 0xc00)  # RN, RD, RU, RZ; native x86 fenv ABI.
INEXACT, UNDERFLOW, OVERFLOW = 32, 16, 8


def decode(bits: tuple[int, int], p: int) -> tuple[int, int]:
    lo, hi = bits
    if p == 24:
        sign, exponent, mantissa = lo >> 31, (lo >> 23) & 255, lo & 0x7fffff
        bias = 127
        if exponent:
            mantissa |= 1 << 23
    else:
        sign, exponent, mantissa, bias = hi >> 15, hi & 0x7fff, lo, 16383
    return (-mantissa if sign else mantissa), (exponent or 1) - bias - (p - 1)


def rounded(integer: int, exponent: int, p: int, mode: int, zero_negative: bool = False) -> tuple[int, int, int]:
    """Integer quotient/remainder implements one IEEE rounding, ties to even."""
    emin, emax, bias = (-126, 127, 127) if p == 24 else (-16382, 16383, 16383)
    sign = integer < 0 if integer else zero_negative
    value = abs(integer)
    if not value:
        return (int(sign) << 31, 0, 0) if p == 24 else (0, int(sign) << 15, 0)
    top = value.bit_length() - 1 + exponent
    unit = max(top - p + 1, emin - p + 1)
    shift = unit - exponent
    denominator = 1 << max(shift, 0)
    quotient, remainder = divmod(value << max(-shift, 0), denominator)
    if remainder:
        if mode == 0:
            quotient += 2 * remainder > denominator or (2 * remainder == denominator and quotient & 1)
        elif mode == (0x400 if sign else 0x800):
            quotient += 1
    if quotient.bit_length() > p:
        quotient >>= 1
        unit += 1
    top = quotient.bit_length() - 1 + unit
    flags = INEXACT if remainder else 0
    if top > emax:
        flags = OVERFLOW | INEXACT
        infinity = mode == 0 or mode == (0x400 if sign else 0x800)
        if p == 24:
            return (int(sign) << 31) | (0x7f800000 if infinity else 0x7f7fffff), 0, flags
        return (1 << 63) if infinity else (1 << 64)-1, (int(sign) << 15) | (0x7fff if infinity else 0x7ffe), flags
    if top < emin and remainder:
        flags |= UNDERFLOW
    stored_exp = 0 if top < emin else top + bias
    if p == 24:
        return (int(sign) << 31) | (stored_exp << 23) | (quotient & 0x7fffff), 0, flags
    return quotient, (int(sign) << 15) | stored_exp, flags


def literal(text: str, p: int) -> tuple[int, int]:
    value, exponent = text.lower().split('p')
    negative = value.startswith('-')
    value = value.lstrip('+-')[2:]
    whole, _, fraction = value.partition('.')
    integer = int(whole + fraction, 16) * (-1 if negative else 1)
    lo, hi, flags = rounded(integer, int(exponent) - 4 * len(fraction), p, 0, negative)
    assert flags == 0, text
    return lo, hi


def unbounded_tiny(integer: int, exponent: int, p: int, mode: int) -> bool:
    """Intel SDM 4.9.1.5: precision rounding with an unbounded exponent."""
    if integer == 0:
        return False
    sign, value = integer < 0, abs(integer)
    top = value.bit_length() - 1 + exponent
    unit = top - p + 1
    shift = unit - exponent
    denominator = 1 << max(shift, 0)
    quotient, remainder = divmod(value << max(-shift, 0), denominator)
    if remainder:
        if mode == 0:
            quotient += 2 * remainder > denominator or (2 * remainder == denominator and quotient & 1)
        elif mode == (0x400 if sign else 0x800):
            quotient += 1
    rounded_top = quotient.bit_length() - 1 + unit
    return rounded_top < (-126 if p == 24 else -16382)


def fma_expected(x: tuple[int, int], y: tuple[int, int], z: tuple[int, int], p: int, mode: int) -> tuple[int, int, int]:
    a, ae = decode(x, p)
    b, be = decode(y, p)
    c, ce = decode(z, p)
    e = min(ae + be, ce)
    exact = ((a * b) << (ae + be - e)) + (c << (ce - e))
    sign_bit = (lambda v: v[0] >> 31) if p == 24 else (lambda v: v[1] >> 15)
    product_sign = sign_bit(x) ^ sign_bit(y)
    zero_negative = mode == 0x400
    if a * b == 0 and c == 0 and product_sign == sign_bit(z):
        zero_negative = bool(product_sign)
    lo, hi, flags = rounded(exact, e, p, mode, zero_negative)
    flags &= ~UNDERFLOW
    if flags & INEXACT and unbounded_tiny(exact, e, p, mode):
        flags |= UNDERFLOW
    return lo, hi, flags


def nextafter_expected(x, y):
    a, ae = decode(x, 64)
    b, be = decode(y, 64)
    e = min(ae, be, -16446)
    left, right = a << (ae-e), b << (be-e)
    if left == right:
        return (*y, 0)
    direction = 1 if right > left else -1
    # Round x +/- half the smallest subnormal toward y. This specifies the
    # next representable value using exact arithmetic, independent of encoding
    # increment/decrement or the runtime's exponent/sign predicates.
    lo, hi, _ = rounded(left + (direction << (-16446-e)), e, 64,
                        0x800 if direction > 0 else 0x400, a < 0)
    flags = UNDERFLOW | INEXACT if hi & 0x7fff == 0 else 0
    return lo, hi, flags


def vectors() -> list[dict]:
    cases = []
    def add(name, kind, x, y, z=(0, 0), special=None):
        for mode in MODES:
            for sticky in (0, 4 | INEXACT):
                expected = special
                if expected is None:
                    expected = nextafter_expected(x,y) if kind == 3 else ((*x, 0) if kind == 2 else fma_expected(x, y, z, 24 if kind == 0 else 64, mode))
                cases.append(dict(name=name, input=(kind, mode, sticky, *x, *y, *z), expected=(*expected[:2], expected[2] | sticky, mode)))
    raw = (
        ('-0x1.001p-81', '0x1.ffe002p-70', '0x1.0002p-133'),
        ('0x1.01008p-75', '0x1.fe01p-76', '0x1p-128'),
        ('0x1.01008p-75', '0x1.fe01p-76', '-0x1p-128'),
        ('-0x1.002002p-75', '-0x1.ffc004p-76', '0x1p-142'),
        ('-0x1.002002p-75', '0x1.ffc004p-76', '0x1p-142'),
        ('0x1.43cb1ep-75', '0x1.94cd22p-76', '0x1.f8p-144'),
        ('0x1.43cb1ep-75', '0x1.94cd22p-76', '-0x1.f8p-144'),
    )
    for i, row in enumerate(raw):
        add(f'fmaf/libc-test/{i}', 0, *(literal(s, 24) for s in row))
    # Every discarded-bit count and signs, including exact midpoints and their
    # adjacent factors, zero/min-subnormal and subnormal/min-normal carries.
    for exponent in range(-150, -124):
        for offset in (-1, 0, 1):
            for sign in (0, 0x80000000):
                x = literal('0x1p-75', 24)
                ylo, yhi = literal(f'0x1p{exponent + 75:+}', 24)
                y = (ylo + offset, yhi)
                for zlo in (0, 1, 2, 0x7ffffe, 0x7fffff, 0x800000, 0x800001):
                    add(f'fmaf/spacing/{exponent}/{offset}/{sign}/{zlo}', 0, (x[0] | sign, 0), y, (zlo, 0))
    rng = random.Random(0x9fa28ece)
    for i in range(1024):
        row = []
        for exponent in (rng.randrange(45, 72), rng.randrange(45, 72), rng.randrange(0, 4)):
            row.append(((rng.getrandbits(1) << 31) | (exponent << 23) | rng.getrandbits(23), 0))
        add(f'fmaf/subnormal-random/{i}', 0, *row)
    for p, kind in ((24, 0), (64, 1)):
        for signs in range(8):
            row = [literal(('-' if signs & (1 << i) else '') + '0x0p+0', p) for i in range(3)]
            add(f'fma{p}/signed-zero/{signs}', kind, *row)
    for yexp in range(-6450, -6438):
        for low in (0, 1, 0x800, 0x801, (1 << 63)-1):
            for sign in (0, 0x8000):
                for zlo in ((1 << 63)-2, (1 << 63)-1, 1 << 63, (1 << 63)+1):
                    z = (zlo, int(zlo >= 1 << 63))
                    y = ((1 << 63) | low, 16383 + yexp)
                    xlo, xhi = literal('-0x1p-10000', 64)
                    add(f'fmal/tiny-boundary/{yexp}/{low}/{sign}/{zlo}', 1, (xlo, xhi ^ sign), y, z)
                    add(f'fmal/negative-tiny-boundary/{yexp}/{low}/{sign}/{zlo}', 1, (xlo, xhi ^ sign ^ 0x8000), y, (z[0], z[1] ^ 0x8000))
    add('fmal/libc-test', 1, literal('-0x1p-10000',64), literal('0x1.0000000000001p-6445',64), literal('0x1p-16382',64))
    for raw_x in (0, 1, 2, 0x7ffffc, 0x7ffffe, 0x7fffff, 0x800000, 0x800001, 0x3f800000, 0x7f7fffff):
        for sign in (0, 0x80000000):
            add(f'powf/identity/{sign | raw_x:x}', 2, (raw_x | sign, 0), (0x3f800000, 0))
    # Special values never enter the corrected finite powf branch. Check raw
    # payloads and invalid flags, plus FMA infinite cancellation and 0*infinity.
    for bits, result, flags in ((0x7f800000,0x7f800000,0),(0xff800000,0xff800000,0),(0x7fc00041,0x7fc00041,0),(0x7f800042,0x7fc00042,1)):
        add(f'powf/special/{bits:x}',2,(bits,0),(0x3f800000,0),special=(result,0,flags))
    for bits, flags in ((0x7fc00041,0),(0x7f800042,1)):
        add(f'fmaf/nan/{bits:x}',0,(bits,0),(0x3f800000,0),(0,0),special=(bits|0x400000,0,flags))
    for bits, flags in (((1 << 63) | (1 << 62) | 0x41,0), ((1 << 63) | 0x42,1)):
        add(f'fmal/nan/{bits:x}',1,(bits,0x7fff),literal('0x1p+0',64),(0,0),special=(bits | (1 << 62),0x7fff,flags))
    for sign in (0, 0x8000):
        add(f'fmal/infinity/{sign}',1,(1 << 63,0x7fff | sign),literal('0x1p+0',64),(0,0),special=(1 << 63,0x7fff | sign,0))
    add('fmal/invalid-zero-infinity',1,(0,0),(1 << 63,0x7fff),(0,0),special=(0xc000000000000000,0xffff,1))
    add('fmaf/invalid-zero-infinity',0,(0,0),(0x7f800000,0),(0,0),special=(0xffc00000,0,1))
    for sign in (0,0x8000):
        for mantissa, exponent in ((0,0),(1,0),(2,0),((1 << 63)-2,0),((1 << 63)-1,0),(1 << 63,1),((1 << 63)+1,1),((1 << 64)-1,1),(1 << 63,2)):
            x = (mantissa, exponent | sign)
            for y in ((0,0),(0,0x8000),literal('0x1p+0',64),literal('-0x1p+0',64)):
                add(f'nextafterl/boundary/{mantissa}/{exponent}/{sign}/{y}',3,x,y)
    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = vectors()
    data = b''.join(struct.pack('<9Q', *case['input']) for case in cases)
    (args.output / 'inputs.bin').write_bytes(data)
    (args.output / 'expectations.json').write_text(json.dumps(cases, indent=2) + '\n')
    summary = dict(vector_count=len(cases), input_sha256=hashlib.sha256(data).hexdigest(), rounding_modes=list(MODES), existing_flags=[0,36], arms={})
    oracle_records = []
    for arm in ('oracle','candidate'):
        binary = getattr(args, arm)
        completed = subprocess.run([str(binary.resolve())], input=data, capture_output=True)
        (args.output / f'{arm}.records').write_bytes(completed.stdout)
        (args.output / f'{arm}.stderr').write_bytes(completed.stderr)
        failures = []
        if completed.returncode or len(completed.stdout) != len(cases)*32:
            raise SystemExit(f'{arm} transport failed: status={completed.returncode}, bytes={len(completed.stdout)}')
        actual_records = list(struct.iter_unpack('<4Q', completed.stdout))
        if arm == 'oracle':
            oracle_records = actual_records
        boundary_records = []
        denormal_differences = []
        for index, (case, actual) in enumerate(zip(cases, actual_records)):
            # x86 additionally exposes a denormal-operand status bit (2).
            # Retain it in raw records; it is not an IEEE arithmetic exception.
            checked = (*actual[:2], actual[2] & 61, actual[3])
            expected = tuple(case['expected'])
            if arm == 'candidate' and (actual[2] ^ oracle_records[index][2]) & 2:
                # The finite powf identity now executes no floating arithmetic;
                # this intentionally avoids the oracle's denormal-operand flag.
                explained = case['input'][0] == 2 and case['input'][3] & 0x7fffffff < 0x800000 and not (actual[2] & 2)
                denormal_differences.append(dict(index=index, name=case['name'], oracle=oracle_records[index], candidate=actual, explained_finite_powf_identity=explained))
                if not explained:
                    failures.append(dict(**case, actual=actual, reason='unexplained x86 denormal flag difference'))
            kind = case['input'][0]
            min_normal = (0x800000, 0) if kind == 0 else (1 << 63, 1)
            magnitude = (expected[0] & 0x7fffffff, 0) if kind == 0 else (expected[0], expected[1] & 0x7fff)
            if kind in (0, 1) and magnitude == min_normal and expected[2] & INEXACT:
                # Tininess is judged independently at precision p with an
                # unbounded exponent; retain the final min-normal records.
                boundary_records.append(dict(index=index, name=case['name'], expected=expected, actual=actual, oracle=oracle_records[index], oracle_result_correct=tuple(oracle_records[index][:2]) == expected[:2]))
            if checked != expected:
                failures.append(dict(**case, actual=actual, compared_expected=expected))
        (args.output / f'{arm}.denormal-differences.json').write_text(json.dumps(denormal_differences, indent=2) + '\n')
        (args.output / f'{arm}.failures.json').write_text(json.dumps(failures, indent=2) + '\n')
        (args.output / f'{arm}.min-normal-boundary.json').write_text(json.dumps(boundary_records, indent=2) + '\n')
        summary['arms'][arm] = dict(min_normal_boundary_records=len(boundary_records), denormal_flag_differences=len(denormal_differences), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), process_status=completed.returncode, vector_failures=len(failures))
    (args.output / 'report.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))
    return int(summary['arms']['candidate']['vector_failures'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
