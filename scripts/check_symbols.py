#!/usr/bin/env python3
"""Compare crabc's public dynamic libc ABI with the pinned musl oracle.

The report judges ABI-significant dynamic-symbol metadata only: name,
FUNC/OBJECT/TLS class, weak/strong binding, and visibility. ELF sizes remain in
the manifests for investigation but are not compared because function size is
not part of its public ABI.
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
PUBLIC_TYPES = frozenset(("FUNC", "OBJECT", "TLS"))
PUBLIC_BINDINGS = frozenset(("GLOBAL", "WEAK"))
PUBLIC_VISIBILITIES = frozenset(("DEFAULT", "PROTECTED"))


@dataclass(frozen=True, order=True)
class DynamicSymbol:
    """One defined, public dynamic ELF symbol, excluding non-ABI code size."""

    name: str
    symbol_type: str
    binding: str
    visibility: str
    size: str

    def tsv_row(self) -> tuple[str, str, str, str, str]:
        return (self.name, self.symbol_type, self.binding, self.visibility, self.size)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference",
        type=Path,
        default=Path(os.environ.get("MUSL_REFERENCE_SO", "/opt/musl-1.2.6/lib/libc.so")),
        help="pinned musl libc.so (default: %(default)s)",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        default=Path(os.environ.get("CRABC_CANDIDATE_SO", ROOT_DIR / "target/debug/libc.so")),
        help="crabc libc.so (default: %(default)s)",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path(os.environ.get("SYMBOL_REPORT_DIR", ROOT_DIR / "compat/reports/symbols")),
        help="directory for machine-readable reports (default: %(default)s)",
    )
    return parser.parse_args()


def dynamic_symbols(library: Path) -> list[DynamicSymbol]:
    """Return defined externally visible public symbols from ELF's .dynsym table."""

    try:
        result = subprocess.run(
            ("readelf", "--wide", "--dyn-syms", str(library)),
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError("readelf is required but was not found on PATH") from error
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"readelf failed for {library}: {error.stderr.strip()}"
        ) from error

    symbols: set[DynamicSymbol] = set()
    for raw_line in result.stdout.splitlines():
        fields = raw_line.split(maxsplit=7)
        if len(fields) != 8 or not fields[0].endswith(":") or not fields[0][:-1].isdigit():
            continue

        _, _value, size, symbol_type, binding, visibility, section_index, name = fields
        if (
            symbol_type not in PUBLIC_TYPES
            or binding not in PUBLIC_BINDINGS
            or visibility not in PUBLIC_VISIBILITIES
            or section_index == "UND"
            or not name
        ):
            continue

        symbols.add(
            DynamicSymbol(
                name=name.split("@", maxsplit=1)[0],
                symbol_type=symbol_type,
                binding=binding,
                visibility=visibility,
                size=size,
            )
        )

    by_name: dict[str, set[DynamicSymbol]] = {}
    for symbol in symbols:
        by_name.setdefault(symbol.name, set()).add(symbol)
    conflicts = {
        name: records for name, records in by_name.items() if len(records) > 1
    }
    if conflicts:
        detail = "; ".join(
            f"{name}: {', '.join('/'.join(record.tsv_row()[1:]) for record in sorted(records))}"
            for name, records in sorted(conflicts.items())
        )
        raise RuntimeError(f"conflicting public dynamic-symbol records in {library}: {detail}")

    return sorted(symbols)


def write_tsv(path: Path, symbols: list[DynamicSymbol]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerows(symbol.tsv_row() for symbol in symbols)


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def main() -> int:
    arguments = parse_arguments()
    for library in (arguments.reference, arguments.candidate):
        if not library.is_file():
            raise RuntimeError(f"shared library not found: {library}")

    reference_symbols = dynamic_symbols(arguments.reference)
    candidate_symbols = dynamic_symbols(arguments.candidate)
    arguments.report_dir.mkdir(parents=True, exist_ok=True)
    write_tsv(arguments.report_dir / "musl-1.2.6-aarch64.dynamic.tsv", reference_symbols)
    write_tsv(arguments.report_dir / "crabc-aarch64.dynamic.tsv", candidate_symbols)

    reference_by_name = {symbol.name: symbol for symbol in reference_symbols}
    candidate_by_name = {symbol.name: symbol for symbol in candidate_symbols}
    missing = sorted(reference_by_name.keys() - candidate_by_name.keys())
    unexpected = sorted(candidate_by_name.keys() - reference_by_name.keys())
    mismatches = []
    for name in sorted(reference_by_name.keys() & candidate_by_name.keys()):
        expected = reference_by_name[name]
        actual = candidate_by_name[name]
        if (
            expected.symbol_type,
            expected.binding,
            expected.visibility,
        ) != (
            actual.symbol_type,
            actual.binding,
            actual.visibility,
        ):
            mismatches.append(
                "\t".join(
                    (
                        name,
                        f"expected={expected.symbol_type}/{expected.binding}/{expected.visibility}",
                        f"actual={actual.symbol_type}/{actual.binding}/{actual.visibility}",
                    )
                )
            )

    write_lines(arguments.report_dir / "missing-from-crabc.txt", missing)
    write_lines(arguments.report_dir / "unexpected-in-crabc.txt", unexpected)
    write_lines(arguments.report_dir / "metadata-mismatches.tsv", mismatches)
    summary = {
        "reference": str(arguments.reference),
        "candidate": str(arguments.candidate),
        "reference_public_dynamic_symbols": str(len(reference_symbols)),
        "candidate_public_dynamic_symbols": str(len(candidate_symbols)),
        "missing_from_candidate": str(len(missing)),
        "unexpected_in_candidate": str(len(unexpected)),
        "metadata_mismatches": str(len(mismatches)),
    }
    write_lines(
        arguments.report_dir / "summary.txt",
        [f"{key}: {value}" for key, value in summary.items()],
    )
    print((arguments.report_dir / "summary.txt").read_text(encoding="utf-8"), end="")
    return int(bool(missing or unexpected or mismatches))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
