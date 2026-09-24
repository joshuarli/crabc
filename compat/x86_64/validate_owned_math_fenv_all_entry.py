#!/usr/bin/env python3
"""Validate framing around the retained installed math/fenv record stream."""

from __future__ import annotations

from pathlib import Path
import struct
import sys

MAGIC = 0x4D464131
FRAME = struct.Struct("<IHH i II")
# x86 MXCSR ABI constants used by the driver after it first clears all flags.
CALLER_ROUNDING = 0x800  # FE_UPWARD
CALLER_EXCEPTIONS = 0x24  # FE_DIVBYZERO | FE_INEXACT
STAGES = (
    (1, "fenv-sensitive-aggregate", 0),
    (2, "fenv-rounding", 0),
    (3, "fdim", 0),
    (4, "exp10", 32 * 2 * 4 * 4 * 8),
    (5, "exp10f", 32 * 2 * 4 * 4 * 8),
    (6, "long-double-completion", 247 * 42),
    (7, "elementary-long-double", 2764 * 40),
    (8, "special", 5544 * 32),
    (9, "complex", 5712 * 64),
    (10, "abi-boundary", 58984 * 64),
)
EXPECTED_SIZE = sum(2 * FRAME.size + body for _, _, body in STAGES)


class ValidationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def frame(data: bytes, offset: int, stage: int, phase: int) -> tuple[int, int]:
    require(offset + FRAME.size <= len(data), f"stage {stage} has a partial frame")
    magic, observed_stage, observed_phase, status, rounding, exceptions = FRAME.unpack_from(data, offset)
    require(magic == MAGIC, f"stage {stage} frame magic differs")
    require(observed_stage == stage and observed_phase == phase,
            f"stage {stage} framing order differs")
    require(status == 0, f"stage {stage} frame reported status {status}")
    require((rounding, exceptions) == (CALLER_ROUNDING, CALLER_EXCEPTIONS),
            f"stage {stage} frame did not preserve the fixed caller fenv state")
    return rounding, exceptions


def validate_bytes(data: bytes) -> None:
    require(len(data) == EXPECTED_SIZE,
            f"installed math/fenv stream has {len(data)} bytes, expected {EXPECTED_SIZE}")
    offset = 0
    for stage, label, body_size in STAGES:
        begin_rounding, begin_exceptions = frame(data, offset, stage, 1)
        offset += FRAME.size
        offset += body_size
        end_rounding, end_exceptions = frame(data, offset, stage, 2)
        require((end_rounding, end_exceptions) == (begin_rounding, begin_exceptions),
                f"{label} did not return to the driver caller fenv state")
        offset += FRAME.size
    require(offset == len(data), "installed math/fenv stream has trailing bytes")


def validate(path: Path) -> None:
    validate_bytes(path.read_bytes())


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} RECORDS", file=sys.stderr)
        return 2
    try:
        validate(Path(sys.argv[1]))
    except (OSError, ValidationError) as error:
        print(f"owned math/fenv records: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
