#!/usr/bin/env python3
"""Exact source roster for the installed math/fenv all-entry component.

The component deliberately composes four already-complete C ABI capability
surfaces.  It does not turn the separate scalar ``sqrt``/``sqrtf`` fenv probe
into an installed claim: ``sqrtl`` belongs to elementary-long-double and the
three ``csqrt*`` entries belong to the complex capability.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
COVERAGE_PATH = Path("compat/crabc-rs/coverage.toml")
CAPABILITY_IDS = (
    "math.elementary-long-double",
    "math.elementary-fenv-sensitive",
    "math.special",
    "math.complex",
)
EXPECTED_COUNTS = {
    "math.elementary-long-double": 35,
    "math.elementary-fenv-sensitive": 15,
    "math.special": 90,
    "math.complex": 66,
}

# Each object is independently translated through the installed dynamic
# driver.  Main exclusions retain the current private probes unchanged while
# the driver gives their observations one ordered installed-product boundary.
OBJECT_ROLES = (
    ("driver", "compat/x86_64/owned_math_fenv_all_entry_driver.c", None),
    ("elementary-long-double", "compat/x86_64/libc_math_elementary_long_double_probe.c", "CRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING"),
    ("fenv-sensitive-aggregate", "compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_probe.c", None),
    ("fenv-rounding", "compat/x86_64/libc_fenv_rounding_probe.c", "CRABC_FENV_ROUNDING_FREESTANDING"),
    ("fdim", "compat/x86_64/libc_fdim_probe.c", "CRABC_FDIM_FREESTANDING"),
    ("exp10", "compat/x86_64/libc_math_exp10_probe.c", "CRABC_MATH_EXP10_FREESTANDING"),
    ("exp10f", "compat/x86_64/libc_math_exp10f_probe.c", "CRABC_MATH_EXP10F_FREESTANDING"),
    ("long-double-completion", "compat/x86_64/libc_math_long_double_completion_probe.c", "CRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING"),
    ("special", "compat/x86_64/libc_math_special_probe.c", "CRABC_MATH_SPECIAL_FREESTANDING"),
    ("complex", "compat/x86_64/libc_math_complex_complete_probe.c", "CRABC_MATH_COMPLEX_COMPLETE_FREESTANDING"),
)


class ContractError(ValueError):
    """The fixed capability roster no longer describes the installed slice."""


def _coverage(root: Path) -> dict[str, dict]:
    document = tomllib.loads((root / COVERAGE_PATH).read_text(encoding="utf-8"))
    records = document.get("capability")
    if not isinstance(records, list):
        raise ContractError("coverage has no capability records")
    found = {record.get("id"): record for record in records if isinstance(record, dict)}
    if any(identifier not in found for identifier in CAPABILITY_IDS):
        raise ContractError("coverage omitted an installed math/fenv capability")
    return {identifier: found[identifier] for identifier in CAPABILITY_IDS}


def load_roster(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    """Return the four exact, disjoint selected C ABI symbol sets.

    ``coverage.toml`` owns the three literal symbol lists.  Its complex
    patterns intentionally avoid hand-maintaining another 66-name list; the
    existing parity validator owns that exact frozen expansion.
    """
    records = _coverage(root)
    try:
        import validate_parity_ledger as ledger
    except ImportError as error:  # pragma: no cover - source layout failure
        raise ContractError("cannot load exact complex baseline") from error

    result: dict[str, tuple[str, ...]] = {}
    for identifier in CAPABILITY_IDS[:-1]:
        symbols = records[identifier].get("symbols")
        if not isinstance(symbols, list) or not all(isinstance(item, str) for item in symbols):
            raise ContractError(f"{identifier} lacks an exact symbol list")
        result[identifier] = tuple(symbols)

    patterns = records["math.complex"].get("symbol_patterns")
    complex_symbols = tuple(ledger.MATH_COMPLEX_COMPLETE_SYMBOLS)
    if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
        raise ContractError("math.complex lacks exact source patterns")
    if not complex_symbols or any(
        not any(fnmatchcase(symbol, pattern) for pattern in patterns)
        for symbol in complex_symbols
    ):
        raise ContractError("exact complex baseline escapes coverage patterns")
    result["math.complex"] = complex_symbols

    if {key: len(value) for key, value in result.items()} != EXPECTED_COUNTS:
        raise ContractError("math/fenv capability counts drifted")
    symbols = tuple(symbol for group in result.values() for symbol in group)
    if len(symbols) != 206 or len(set(symbols)) != len(symbols):
        raise ContractError("math/fenv capability surfaces are not the expected disjoint 206")
    if "sqrtl" not in result["math.elementary-long-double"]:
        raise ContractError("elementary-long-double lost sqrtl")
    if "sqrt" in symbols or "sqrtf" in symbols:
        raise ContractError("scalar sqrt/sqrtf escaped their separate probe")
    if not {"csqrt", "csqrtf", "csqrtl"}.issubset(result["math.complex"]):
        raise ContractError("complex sqrt surface is incomplete")
    return result
