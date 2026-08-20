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
OS_TEST_REPORT = ROOT_DIR / "compat/reports/os-test/latest.json"
PTHREAD_STRESS_REPORT = ROOT_DIR / "compat/reports/pthread-stress/latest.json"
SIGNAL_PROCESS_REPORT = ROOT_DIR / "compat/reports/signal-process.json"
RESOLVER_NETWORK_REPORT = ROOT_DIR / "compat/reports/resolver-network.json"
LOADER_FEATURE_REPORT = ROOT_DIR / "compat/abi/crabc/aarch64/loader-features.json"
LDSO_REPORT = ROOT_DIR / "compat/reports/ldso/latest.json"


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


def m6_report_state(path: Path, expected_runner: str) -> dict[str, Any] | None:
    """Return a named M6 report only when it is structurally identifiable."""

    report = read_json(path)
    if report is None:
        return None
    runner = report.get("runner", report.get("harness"))
    if runner != expected_runner:
        raise RuntimeError(f"unexpected M6 report identity in {path}: {runner!r}")
    report["_path"] = str(path.relative_to(ROOT_DIR))
    return report


def m7_report_state() -> dict[str, Any] | None:
    """Return the synthetic loader report only when it has its runner identity."""

    report = read_json(LDSO_REPORT)
    if report is None:
        return None
    if report.get("schema") != 1 or report.get("runner") != "compat/ldso/run.py":
        raise RuntimeError(f"unexpected M7 report identity in {LDSO_REPORT}")
    cases = report.get("cases")
    if report.get("result") == "pass" and not isinstance(cases, dict):
        raise RuntimeError(f"M7 pass report has invalid cases in {LDSO_REPORT}")
    report["_path"] = str(LDSO_REPORT.relative_to(ROOT_DIR))
    return report


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
    os_test = m6_report_state(OS_TEST_REPORT, "pinned-os-test")
    pthread_stress = m6_report_state(PTHREAD_STRESS_REPORT, "crabc-pthread-stress")
    signal_process = m6_report_state(SIGNAL_PROCESS_REPORT, "crabc-signal-process")
    resolver_network = m6_report_state(RESOLVER_NETWORK_REPORT, "compat/resolver-network")
    loader_features = loader_feature_state()
    ldso = m7_report_state()

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
                    (
                        "verified",
                        "not measured",
                        "symbol-level verification is not inferred from subsystem evidence",
                    ),
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

    lines.extend(["", "## M7 synthetic loader differential evidence", ""])
    if ldso is None:
        lines.append("No synthetic loader result. Run `./scripts/dev.sh ldso`.")
    else:
        cases = ldso.get("cases", {})
        if not isinstance(cases, dict):
            raise RuntimeError(f"invalid M7 cases in {ldso['_path']}")
        passed = all(
            isinstance(case, dict) and case.get("result") == "pass"
            for case in cases.values()
        )
        lines.append(
            f"Synthetic AArch64 loader comparison: "
            f"**{'pass' if ldso.get('result') == 'pass' and passed else 'FAIL'}** "
            f"({len(cases)} case(s), timeout={ldso.get('timeout_seconds', 'unknown')}s); "
            f"report `{ldso['_path']}`."
        )
        if cases:
            lines.append("")
            lines.extend(
                markdown_table(
                    ("case", "result"),
                    [
                        (name, case.get("result", "unknown"))
                        for name, case in sorted(cases.items())
                        if isinstance(case, dict)
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

    lines.extend(["", "## M6 standards and stress evidence", ""])
    if os_test is None:
        lines.append("No pinned os-test profile result. Run `./scripts/dev.sh os-test`.")
    else:
        suites = os_test.get("suites", [])
        if not isinstance(suites, list):
            raise RuntimeError(f"invalid os-test suites in {os_test['_path']}")
        passed = sum(item.get("passed") is True for item in suites if isinstance(item, dict))
        lines.append(
            f"Pinned os-test ({os_test.get('os_test_revision', 'unknown')}): "
            f"**{'pass' if os_test.get('passed') is True else 'FAIL'}** "
            f"({passed}/{len(suites)} selected suite(s)); report `{os_test['_path']}`."
        )
        if suites:
            lines.append("")
            lines.extend(
                markdown_table(
                    (
                        "suite",
                        "oracle",
                        "result",
                        "source contract",
                        "outcome differences",
                        "raw runtime differences",
                        "crabc source failures",
                        "musl source failures",
                        "source improvements",
                    ),
                    [
                        (
                            item.get("suite", "unknown"),
                            item.get("oracle", "pinned-musl-differential"),
                            item.get("result", "unknown"),
                            (
                                item.get("source_contract_passed")
                                if item.get("source_contract_passed") is not None
                                else "n/a"
                            ),
                            item.get("difference_count", "unknown"),
                            item.get("runtime_difference_count", "unknown"),
                            item.get("candidate_source_failure_count", 0),
                            item.get("musl_source_failure_count", 0),
                            item.get("source_improvement_count", 0),
                        )
                        for item in suites
                        if isinstance(item, dict)
                    ],
                )
            )

    if pthread_stress is None:
        lines.append("\nNo pthread/TLS stress result. Run `./scripts/dev.sh pthread-stress`.")
    else:
        comparisons = pthread_stress.get("comparisons", {})
        exact_streams = (
            comparisons.get("all_exit_status_match") is True
            and comparisons.get("all_stdout_match") is True
            and comparisons.get("all_stderr_match") is True
            and comparisons.get("all_completed") is True
            if isinstance(comparisons, dict)
            else False
        )
        lines.append(
            f"\nPthread/TLS stress differential: "
            f"**{'pass' if pthread_stress.get('passed') is True else 'FAIL'}** "
            f"({pthread_stress.get('completed_iterations', 'unknown')}/"
            f"{pthread_stress.get('iteration_count', 'unknown')} iterations, "
            f"timeout={pthread_stress.get('timeout_seconds', 'unknown')}s, "
            f"exact streams={exact_streams}, source improvements="
            f"{pthread_stress.get('source_improvement_count', 0)}); "
            f"report `{pthread_stress['_path']}`."
        )

    if signal_process is None:
        lines.append("\nNo signal/process result. Run `./scripts/dev.sh signal-process`.")
    else:
        cases = signal_process.get("cases", {})
        case_count = len(cases) if isinstance(cases, dict) else "unknown"
        comparisons = signal_process.get("comparisons", {})
        exact_streams = (
            comparisons.get("all_exit_status_match") is True
            and comparisons.get("all_stdout_match") is True
            and comparisons.get("all_stderr_match") is True
            if isinstance(comparisons, dict)
            else False
        )
        lines.append(
            f"\nSignal/process isolated comparison: "
            f"**{'pass' if signal_process.get('passed') is True else 'FAIL'}** "
            f"({case_count} subcase(s), exact streams={exact_streams}); "
            f"report `{signal_process['_path']}`."
        )

    if resolver_network is None:
        lines.append("\nNo deterministic resolver/network result. Run `./scripts/dev.sh resolver-network`.")
    else:
        contract = resolver_network.get("contract", {})
        expected_subcases = contract.get("expected_subcases", []) if isinstance(contract, dict) else []
        case_count = len(expected_subcases) if isinstance(expected_subcases, list) else "unknown"
        dns_server = resolver_network.get("dns_server", {})
        event_contract = dns_server.get("event_contract", {}) if isinstance(dns_server, dict) else {}
        event_contract_passed = (
            event_contract.get("passed") is True if isinstance(event_contract, dict) else False
        )
        lines.append(
            f"\nDeterministic local resolver/network comparison: "
            f"**{'pass' if resolver_network.get('passed') is True else 'FAIL'}** "
            f"({case_count} contract item(s), DNS event contract={event_contract_passed}); "
            f"report `{resolver_network['_path']}`."
        )

    lines.extend(
        [
            "",
            "## Unmeasured frontier",
            "",
            "The selected POSIX, signal/process, and resolver/network contracts above are not full "
            "standards conformance. Static candidate ABI parity, exhaustive header declaration/layout parity, "
            "real Alpine corpus, and stock Rust `std` compatibility are not measured by this dashboard yet. "
            "The M7 synthetic suite measures bounded loader contracts; it is not a claim that arbitrary "
            "Alpine DSO graphs are supported.",
            "",
        ]
    )
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
