#!/usr/bin/env python3
"""Turn libc-test execution events and diagnostics into durable reports.

The execution runner deliberately records only one tab-separated event per
test. Keeping parsing here makes linker-output handling testable and keeps JSON
escaping out of the execution loop. The script uses only Python's standard
library because it runs in the pinned native development image.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


MISSING_SYMBOL_PATTERNS = (
    # GNU ld and lld commonly quote the symbol with either `'` or `` ` ``.
    re.compile(r"undefined reference to\s+[`']?([^`'\s]+)[`']?"),
    re.compile(r"undefined symbol(?::|\s)\s*[`']?([^`'\s]+)[`']?"),
    # GNU ld uses this form for some relocation diagnostics.
    re.compile(r"against undefined symbol\s+[`']([^`']+)[`']"),
)


def atomic_write(path: Path, contents: str) -> None:
    """Write a report without leaving a truncated artifact on interruption."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as temporary:
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        # The harness may run as root in Docker while reports are inspected
        # from the bind-mounted checkout by the host user.
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def missing_symbols(diagnostic_file: str) -> list[str]:
    """Extract unique unresolved symbol names from one linker diagnostic."""

    try:
        diagnostic = Path(diagnostic_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    symbols: set[str] = set()
    for line in diagnostic.splitlines():
        for pattern in MISSING_SYMBOL_PATTERNS:
            match = pattern.search(line)
            if match:
                symbol = match.group(1).strip("`'")
                if symbol:
                    symbols.add(symbol)
                break
    return sorted(symbols)


def read_events(path: Path) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as event_file:
        for line_number, fields in enumerate(csv.reader(event_file, delimiter="\t"), 1):
            if not fields or not any(fields):
                continue
            if len(fields) != 6:
                raise ValueError(
                    f"{path}:{line_number}: expected 6 tab-separated fields, got {len(fields)}"
                )
            suite, test_name, status, phase, reason, diagnostic_file = fields
            result = {
                "suite": suite,
                "test": test_name,
                "id": f"{suite}/{test_name}",
                "status": status,
                "phase": phase,
                "reason": reason,
                "missing_symbols": [],
                "diagnostic_file": diagnostic_file,
            }
            if status == "BUILDERROR" and phase == "link":
                result["missing_symbols"] = missing_symbols(diagnostic_file)
                if result["missing_symbols"]:
                    result["reason"] = "missing_symbols"
            events.append(result)
    return events


def json_lines(results: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        for result in results
    )


def graph(results: list[dict[str, object]]) -> dict[str, list[str]]:
    blocked: dict[str, set[str]] = defaultdict(set)
    for result in results:
        test_id = str(result["id"])
        for symbol in result["missing_symbols"]:  # type: ignore[union-attr]
            blocked[str(symbol)].add(test_id)
    return {symbol: sorted(test_ids) for symbol, test_ids in sorted(blocked.items())}


def parse_exported_symbols(value: str) -> int | None:
    return int(value) if value.isdigit() else None


def build_report(args: argparse.Namespace) -> None:
    results = read_events(Path(args.events))
    blocked = graph(results)
    counts = {status: sum(result["status"] == status for result in results) for status in (
        "PASS", "FAIL", "BUILDERROR", "TIMEOUT", "SKIP", "OTHER"
    )}

    atomic_write(Path(args.results), json_lines(results))

    edges = ["symbol\ttest\n"]
    for symbol, test_ids in blocked.items():
        edges.extend(f"{symbol}\t{test_id}\n" for test_id in test_ids)
    atomic_write(Path(args.missing_symbols), "".join(edges))

    missing_graph = [
        {
            "symbol": symbol,
            "blocked_test_count": len(test_ids),
            "blocked_tests": test_ids,
        }
        for symbol, test_ids in blocked.items()
    ]
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subset": args.subset,
        "libc_so": args.libc_so,
        "ldso_so": args.ldso_so,
        "symbols_exported": parse_exported_symbols(args.symbols_exported),
        "counts": {
            "total": len(results),
            "PASS": counts["PASS"],
            "FAIL": counts["FAIL"],
            "BUILDERROR": counts["BUILDERROR"],
            "TIMEOUT": counts["TIMEOUT"],
            "SKIP": counts["SKIP"],
            "Other": counts["OTHER"],
        },
        "reports": {
            "human_summary": Path(args.human_summary).name,
            "raw": Path(args.raw).name,
            "results": Path(args.results).name,
            "missing_symbols": Path(args.missing_symbols).name,
            "events": Path(args.events).name,
        },
        "missing_symbols": missing_graph,
    }
    atomic_write(
        Path(args.report), json.dumps(report, indent=2, sort_keys=True) + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--missing-symbols", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--subset", required=True)
    parser.add_argument("--libc-so", required=True)
    parser.add_argument("--ldso-so", required=True)
    parser.add_argument("--symbols-exported", required=True)
    parser.add_argument("--human-summary", required=True)
    parser.add_argument("--raw", required=True)
    build_report(parser.parse_args())


if __name__ == "__main__":
    main()
