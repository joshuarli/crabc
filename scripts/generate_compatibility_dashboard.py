#!/usr/bin/env python3
"""Generate the AArch64 compatibility dashboard from durable local reports.

The dashboard deliberately distinguishes an ABI export from an implemented or
verified interface.  The current laboratory can measure public dynamic ABI
metadata, selected runtime probes, and libc-test outcomes; it must not turn
those measurements into broader behavioral claims.
"""

from __future__ import annotations

import argparse
import csv
import json
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT_DIR / "COMPATIBILITY.md"
ABI_MANIFEST = ROOT_DIR / "compat/abi/musl-1.2.6/aarch64/manifest.json"
SYMBOL_REPORT_DIR = ROOT_DIR / "compat/reports/symbols"
RATCHET_REPORT = ROOT_DIR / "compat/reports/ratchet.json"
LIBC_TEST_REPORT_DIR = ROOT_DIR / "libc-test-harness/reports"
DIFFERENTIAL_REPORT_DIR = ROOT_DIR / "compat/reports/differential"
LOADER_FEATURE_REPORT = ROOT_DIR / "compat/abi/crabc/aarch64/loader-features.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def read_summary(path: Path) -> dict[str, int] | None:
    if not path.is_file():
        return None
    values: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(": ")
        if separator and value.isdigit():
            values[key] = int(value)
    required = {
        "reference_public_dynamic_symbols",
        "candidate_public_dynamic_symbols",
        "missing_from_candidate",
        "unexpected_in_candidate",
        "metadata_mismatches",
    }
    if not required.issubset(values):
        raise RuntimeError(f"incomplete symbol summary: {path}")
    return values


def symbol_state() -> dict[str, int] | None:
    summary = read_summary(SYMBOL_REPORT_DIR / "summary.txt")
    if summary is None:
        return None
    expected = summary["reference_public_dynamic_symbols"]
    missing = summary["missing_from_candidate"]
    mismatches = summary["metadata_mismatches"]
    return {
        "expected": expected,
        "exported": summary["candidate_public_dynamic_symbols"],
        "missing": missing,
        "unexpected": summary["unexpected_in_candidate"],
        "mismatches": mismatches,
        "exact_matches": expected - missing - mismatches,
    }


def abi_state() -> dict[str, Any] | None:
    return read_json(ABI_MANIFEST)


def libc_test_states() -> list[dict[str, Any]]:
    """Return the newest retained structured report for each libc-test subset."""

    newest: dict[str, dict[str, Any]] = {}
    if not LIBC_TEST_REPORT_DIR.is_dir():
        return []
    for path in LIBC_TEST_REPORT_DIR.glob("report_*.json"):
        report = read_json(path)
        if report is None or report.get("schema_version") != 1:
            continue
        subset = report.get("subset")
        generated_at = report.get("generated_at")
        if not isinstance(subset, str) or not isinstance(generated_at, str):
            continue
        previous = newest.get(subset)
        if previous is None or generated_at > previous["generated_at"]:
            newest[subset] = report
    return [newest[subset] for subset in sorted(newest)]


def differential_state() -> list[dict[str, Any]]:
    if not DIFFERENTIAL_REPORT_DIR.is_dir():
        return []
    reports: list[dict[str, Any]] = []
    for path in sorted(DIFFERENTIAL_REPORT_DIR.glob("*.json")):
        report = read_json(path)
        if report is not None:
            report["_path"] = str(path.relative_to(ROOT_DIR))
            reports.append(report)
    return reports


def loader_feature_state() -> dict[str, Any] | None:
    return read_json(LOADER_FEATURE_REPORT)


def markdown_table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(str(value) for value in row) + " |" for row in rows)
    return lines


def main() -> int:
    args = parse_args()
    with (ROOT_DIR / "compat/upstreams.toml").open("rb") as stream:
        upstreams = tomllib.load(stream)
    symbols = symbol_state()
    abi = abi_state()
    ratchet = read_json(RATCHET_REPORT)
    libc_test = libc_test_states()
    differential = differential_state()
    loader_features = loader_feature_state()

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    lines = [
        "# Compatibility Dashboard",
        "",
        "<!-- Generated by scripts/generate_compatibility_dashboard.py; do not edit manually. -->",
        "",
        f"Generated: `{generated_at}`",
        "",
        "This is a measurement dashboard, not a claim of full musl compatibility. "
        "`exported`, `implemented`, and `verified` remain separate states.",
        "",
        "## Baseline",
        "",
    ]
    lines.extend(
        markdown_table(
            ("field", "value"),
            [
                ("architecture", "AArch64 (`aarch64-unknown-linux-musl`)"),
                ("reference libc", f"musl {upstreams['musl']['version']}"),
                ("Docker platform", upstreams["environment"]["platform"]),
                ("Rust toolchain", upstreams["environment"]["rust_toolchain"]),
            ],
        )
    )

    lines.extend(["", "## Public dynamic-symbol ABI", ""])
    if symbols is None:
        lines.append("No current symbol report. Run `./scripts/dev.sh compat`.")
    else:
        lines.extend(
            markdown_table(
                ("metric", "count", "meaning"),
                [
                    ("expected", symbols["expected"], "pinned musl public dynamic symbols"),
                    ("exported", symbols["exported"], "crabc public dynamic symbols"),
                    ("exact ABI matches", symbols["exact_matches"], "name, kind, binding, and visibility match"),
                    ("metadata mismatches", symbols["mismatches"], "same name, incompatible public ELF metadata"),
                    ("missing", symbols["missing"], "expected musl name absent from crabc"),
                    ("unexpected", symbols["unexpected"], "crabc public name absent from musl"),
                    ("implemented", "not measured", "an export does not prove implementation"),
                    ("verified", 0, "no subsystem has the full verification evidence yet"),
                ],
            )
        )

    lines.extend(["", "## ABI inventory and ratchet", ""])
    if abi is None:
        lines.append("Pinned ABI inventory is unavailable.")
    else:
        dynamic = abi["dynamic"]
        static = abi["static"]
        headers = abi.get("headers")
        header_baseline = (
            f"{headers['records']} files / {headers['public_records']} public"
            if isinstance(headers, dict)
            else "not inventoried"
        )
        lines.extend(
            markdown_table(
                ("surface", "baseline", "candidate measurement"),
                [
                    ("`libc.so` dynamic", f"{dynamic['records']} records", "above"),
                    (
                        "`libc.a` static",
                        f"{static['records']} records / {static['unique_names']} names",
                        "not measured yet",
                    ),
                    ("installed headers", header_baseline, "declaration/layout parity not measured yet"),
                    (
                        "musl loader relationship",
                        "`ld-musl-aarch64.so.1` → `libc.so`",
                        "crabc `libldso.so` needs feature-by-feature evidence",
                    ),
                ],
            )
        )
    if ratchet is None:
        lines.append("\nRatchet has not run. Run `./scripts/dev.sh compat`.")
    else:
        violations = ratchet.get("violations", {})
        violation_count = sum(len(value) for value in violations.values() if isinstance(value, list))
        lines.append(
            f"\nRatchet: **{'pass' if violation_count == 0 else 'FAIL'}** "
            f"({violation_count} regression violation(s))."
        )

    lines.extend(["", "## Loader feature inventory", ""])
    if loader_features is None:
        lines.append("No loader feature inventory. Run `./scripts/dev.sh loader-inventory`.")
    else:
        features = loader_features.get("features", [])
        states: dict[str, int] = {}
        for feature in features if isinstance(features, list) else []:
            if isinstance(feature, dict) and isinstance(feature.get("state"), str):
                states[feature["state"]] = states.get(feature["state"], 0) + 1
        verification = loader_features.get("verification", {})
        verified = bool(verification.get("verified")) if isinstance(verification, dict) else False
        lines.extend(
            markdown_table(
                ("metric", "count", "meaning"),
                [
                    ("inventoried feature slices", len(features), "source and ELF evidence"),
                    ("source + test target", states.get("source_and_test_target", 0), "target exists; result is not asserted"),
                    ("source only", states.get("source_only", 0), "no focused target recorded"),
                    ("not evidenced/surface only", states.get("not_evidenced", 0) + states.get("surface_only", 0), "not implementation proof"),
                    ("verified", int(verified), "runtime execution is tracked separately"),
                ],
            )
        )

    lines.extend(["", "## libc-test", ""])
    if not libc_test:
        lines.append("No structured libc-test result. Run `./scripts/dev.sh libc-test functional`.")
    else:
        lines.extend(
            markdown_table(
                ("subset", "total", "PASS", "FAIL", "BUILDERROR", "TIMEOUT", "SKIP"),
                [
                    (
                        report.get("subset", "unknown"),
                        counts.get("total", "unknown"),
                        counts.get("PASS", "unknown"),
                        counts.get("FAIL", "unknown"),
                        counts.get("BUILDERROR", "unknown"),
                        counts.get("TIMEOUT", "unknown"),
                        counts.get("SKIP", "unknown"),
                    )
                    for report in libc_test
                    for counts in [report.get("counts", {})]
                ],
            )
        )
        lines.append("")
        lines.extend(
            f"`{report.get('subset', 'unknown')}` missing-symbol graph: "
            f"{len(report.get('missing_symbols', []))} blocker symbol(s)."
            for report in libc_test
        )

    lines.extend(["", "## Differential workloads", ""])
    if not differential:
        lines.append("No differential result. Run `./scripts/dev.sh differential`.")
    else:
        passed = sum(report.get("passed") is True for report in differential)
        failed = len(differential) - passed
        lines.append(f"Pass: **{passed}**; fail: **{failed}**.")
        lines.append("")
        lines.extend(
            markdown_table(
                ("case", "result", "errno", "report"),
                [
                    (
                        report.get("case", "unknown"),
                        report.get("result", "unknown"),
                        report.get("errno", {}).get("candidate", "unknown"),
                        f"`{report['_path']}`",
                    )
                    for report in differential
                ],
            )
        )

    lines.extend(
        [
            "",
            "## Unmeasured frontier",
            "",
            "POSIX-suite outcomes, static candidate ABI parity, header declaration/layout parity, "
            "loader runtime-slice results, real Alpine corpus, and stock Rust `std` compatibility are not measured by this dashboard yet. "
            "The focused loader stderr-isolation regression is passing, but it is not a verified loader slice.",
            "",
        ]
    )
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
