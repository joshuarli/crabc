#!/usr/bin/env python3
"""Validate owned static kernel-administration provider ELF metadata."""

from __future__ import annotations

import argparse
from pathlib import Path


PROVIDERS = ("arch_prctl", "iopl", "ioperm")
REQUIRED_METADATA = ("FUNC", "GLOBAL", "DEFAULT")


def validate_table(table: str) -> None:
    """Require one strong default-visible function definition per provider."""

    rows: dict[str, list[list[str]]] = {provider: [] for provider in PROVIDERS}
    for line in table.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in rows:
            rows[fields[7]].append(fields)

    for provider, definitions in rows.items():
        if len(definitions) != 1:
            raise ValueError(
                f"static provider {provider} has {len(definitions)} symbol rows, expected one"
            )
        fields = definitions[0]
        if tuple(fields[3:6]) != REQUIRED_METADATA or fields[6] == "UND":
            actual = " ".join(fields[3:7])
            expected = " ".join(REQUIRED_METADATA)
            raise ValueError(
                f"static provider {provider} must be {expected}, got {actual}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("table", type=Path, help="raw readelf --symbols output")
    args = parser.parse_args()
    try:
        validate_table(args.table.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"kernel-admin static provider metadata: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
