#!/usr/bin/env python3
"""Validate the fixed binary80 fdiml/exp10l/pow10l evidence record format."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


RECORD = struct.Struct("<HHIHHHHI10sHHII")
FE_ALL_EXCEPT = 0x3F
FE_OVERFLOW = 0x08
FE_UNDERFLOW = 0x10
FE_INEXACT = 0x20
ROUNDING = (0x000, 0x400, 0x800, 0xC00)
ID_BINARY80_ABI = 1
ID_FDIML = 2
ID_EXP10L = 3
ID_POW10L = 4
FDIM_CASES = 13
EXP10_CASES = 24
EXPECTED_RECORDS = 3 + len(ROUNDING) * (FDIM_CASES + 2 * EXP10_CASES)


def binary80_exponent(value: bytes) -> int:
    return (value[8] | (value[9] << 8)) & 0x7FFF


def binary80_mantissa(value: bytes) -> int:
    return int.from_bytes(value[:8], "little")


Record = tuple[int, int, int, int, int, int, int, int, bytes, int, int, int, int]


def parse(path: Path) -> list[Record]:
    payload = path.read_bytes()
    if len(payload) != EXPECTED_RECORDS * RECORD.size:
        raise ValueError(
            f"expected {EXPECTED_RECORDS} complete {RECORD.size}-byte records, "
            f"got {len(payload)} bytes"
        )
    return [RECORD.unpack_from(payload, offset) for offset in range(0, len(payload), RECORD.size)]


def assert_environment(record: Record) -> None:
    (
        function,
        case,
        requested,
        x87_round,
        x87_flags,
        mxcsr_round,
        mxcsr_flags,
        combined,
        _,
        x87_control_before,
        x87_control_after,
        mxcsr_control_before,
        mxcsr_control_after,
    ) = record
    del function, case
    if requested not in ROUNDING:
        raise ValueError(f"unknown requested rounding value {requested:#x}")
    if x87_round != requested or mxcsr_round != requested:
        raise ValueError(
            "x87/MXCSR directed-rounding mismatch: "
            f"requested={requested:#x}, x87={x87_round:#x}, mxcsr={mxcsr_round:#x}"
        )
    if x87_flags & ~FE_ALL_EXCEPT or mxcsr_flags & ~FE_ALL_EXCEPT:
        raise ValueError("record contains an out-of-range x87 or MXCSR exception bit")
    if combined != (x87_flags | mxcsr_flags):
        raise ValueError(
            "fetestexcept did not equal the observed x87/MXCSR exception union: "
            f"combined={combined:#x}, x87={x87_flags:#x}, mxcsr={mxcsr_flags:#x}"
        )
    if x87_control_before != x87_control_after:
        raise ValueError(
            "binary80 call did not restore the complete x87 control word: "
            f"before={x87_control_before:#x}, after={x87_control_after:#x}"
        )
    if mxcsr_control_before != mxcsr_control_after:
        raise ValueError(
            "binary80 call did not restore the complete MXCSR control state: "
            f"before={mxcsr_control_before:#x}, after={mxcsr_control_after:#x}"
        )
    if (x87_control_before & 0x0C00) != requested:
        raise ValueError(
            "x87 control snapshot did not retain the requested rounding mode: "
            f"requested={requested:#x}, control={x87_control_before:#x}"
        )
    if ((mxcsr_control_before >> 3) & 0x0C00) != requested:
        raise ValueError(
            "MXCSR control snapshot did not retain the requested rounding mode: "
            f"requested={requested:#x}, control={mxcsr_control_before:#x}"
        )


def validate(records: list[Record]) -> None:
    expected_abi = (
        bytes((0, 0, 0, 0, 0, 0, 0, 0x80, 0x00, 0x40)),
        bytes((0, 0, 0, 0, 0, 0, 0, 0xA0, 0x02, 0x40)),
        bytes((0, 0, 0, 0, 0, 0, 0, 0xA0, 0x02, 0x40)),
    )
    cursor = 0
    for case, expected_value in enumerate(expected_abi):
        record = records[cursor]
        cursor += 1
        function, observed_case, _, _, _, _, _, combined, value, *_ = record
        if function != ID_BINARY80_ABI or observed_case != case:
            raise ValueError("binary80 ABI records are not first and ordered")
        assert_environment(record)
        if combined != 0 or value != expected_value:
            raise ValueError("typed binary80 ABI call changed an exact value or raised an exception")

    fdim_records: dict[tuple[int, int], Record] = {}
    for rounding in ROUNDING:
        for case in range(FDIM_CASES):
            record = records[cursor]
            cursor += 1
            if record[0] != ID_FDIML or record[1] != case or record[2] != rounding:
                raise ValueError("fdiml record order is not stable")
            assert_environment(record)
            fdim_records[(rounding, case)] = record

    exp_records: dict[tuple[int, int, int], Record] = {}
    for function in (ID_EXP10L, ID_POW10L):
        for rounding in ROUNDING:
            for case in range(EXP10_CASES):
                record = records[cursor]
                cursor += 1
                if record[0] != function or record[1] != case or record[2] != rounding:
                    raise ValueError("exp10l/pow10l record order is not stable")
                assert_environment(record)
                exp_records[(function, rounding, case)] = record
    if cursor != len(records):
        raise ValueError("record parser did not consume the complete stream")

    for rounding in ROUNDING:
        for zero_case in (2, 3, 4, 6):
            value = fdim_records[(rounding, zero_case)][8]
            if value != bytes(10):
                raise ValueError(f"fdiml case {zero_case} did not return positive binary80 zero")
        for nan_case in (7, 8, 9, 10):
            value = fdim_records[(rounding, nan_case)][8]
            if binary80_exponent(value) != 0x7FFF or binary80_mantissa(value) == 0:
                raise ValueError(f"fdiml case {nan_case} did not retain a binary80 NaN result")
        if fdim_records[(rounding, 11)][7] & FE_INEXACT == 0:
            raise ValueError("fdiml non-exact subtraction did not record FE_INEXACT")
        if fdim_records[(rounding, 12)][7] & (FE_OVERFLOW | FE_INEXACT) != (FE_OVERFLOW | FE_INEXACT):
            raise ValueError("fdiml overflow did not record FE_OVERFLOW|FE_INEXACT")

        finite = exp_records[(ID_EXP10L, rounding, 16)][8]
        if binary80_exponent(finite) == 0x7FFF or binary80_mantissa(finite) == 0:
            raise ValueError("exp10l finite boundary did not remain finite and nonzero")
        overflow = exp_records[(ID_EXP10L, rounding, 17)]
        if overflow[7] & (FE_OVERFLOW | FE_INEXACT) != (FE_OVERFLOW | FE_INEXACT):
            raise ValueError("exp10l overflow did not record FE_OVERFLOW|FE_INEXACT")
        underflow = exp_records[(ID_EXP10L, rounding, 19)]
        if underflow[7] & (FE_UNDERFLOW | FE_INEXACT) != (FE_UNDERFLOW | FE_INEXACT):
            raise ValueError("exp10l underflow did not record FE_UNDERFLOW|FE_INEXACT")
        for case in range(EXP10_CASES):
            left = exp_records[(ID_EXP10L, rounding, case)]
            right = exp_records[(ID_POW10L, rounding, case)]
            if left[3:] != right[3:]:
                raise ValueError(
                    f"same-address exp10l/pow10l aliases diverged at mode={rounding:#x}, case={case}"
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("records", type=Path)
    args = parser.parse_args()
    validate(parse(args.records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
