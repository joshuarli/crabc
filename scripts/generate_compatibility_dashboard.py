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
STATIC_PTHREAD_TLS_REPORT = ROOT_DIR / "compat/reports/static-pthread-tls/latest.json"
SIGNAL_PROCESS_REPORT = ROOT_DIR / "compat/reports/signal-process.json"
RESOLVER_NETWORK_REPORT = ROOT_DIR / "compat/reports/resolver-network.json"
LOADER_FEATURE_REPORT = ROOT_DIR / "compat/abi/crabc/aarch64/loader-features.json"
LDSO_REPORT = ROOT_DIR / "compat/reports/ldso/latest.json"
CORPUS_REPORT = ROOT_DIR / "compat/reports/corpus/latest.json"
RUST_STD_REPORT = ROOT_DIR / "compat/reports/rust-std/latest.json"
RUST_STD_DEPENDENT_REPORT = ROOT_DIR / "compat/reports/rust-std-dependent/latest.json"
LTO_REPORT = ROOT_DIR / "compat/reports/lto/latest.json"
NATIVE_FACADE_LTO_REPORT = ROOT_DIR / "compat/reports/lto/native-facade/latest.json"
LUA_REPORT = ROOT_DIR / "compat/reports/lua/latest.json"
ABI_PROBE_REPORT = ROOT_DIR / "compat/reports/abi/latest.json"
ENVIRONMENT_REPORT = ROOT_DIR / "compat/reports/environment.json"


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


def environment_state() -> dict[str, Any] | None:
    """Return the source and artifact provenance shared by all evidence lanes."""

    report = read_json(ENVIRONMENT_REPORT)
    if report is None:
        return None
    if not isinstance(report.get("crabc_git_sha"), str):
        raise RuntimeError(f"environment report lacks tested source: {ENVIRONMENT_REPORT}")
    if not isinstance(report.get("crabc_git_dirty"), bool):
        raise RuntimeError(f"environment report lacks tree cleanliness: {ENVIRONMENT_REPORT}")
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RuntimeError(f"environment report lacks artifact provenance: {ENVIRONMENT_REPORT}")
    for key in ("libc_shared", "libc_static", "ldso_shared", "public_headers", "workspace_lock", "oracle_pins"):
        record = artifacts.get(key)
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise RuntimeError(f"environment report lacks {key} provenance: {ENVIRONMENT_REPORT}")
        if record.get("sha256") is not None and not isinstance(record.get("sha256"), str):
            raise RuntimeError(f"environment report has invalid {key} hash: {ENVIRONMENT_REPORT}")
    report["_path"] = str(ENVIRONMENT_REPORT.relative_to(ROOT_DIR))
    return report


def provenance_value(record: dict[str, Any]) -> str:
    """Render a reported hash without claiming an artifact that was absent."""

    digest = record.get("sha256")
    if isinstance(digest, str):
        return f"`{digest}`"
    return "not built"


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


def abi_probe_state() -> dict[str, Any] | None:
    """Read generated static/header evidence without turning triage into green."""

    report = read_json(ABI_PROBE_REPORT)
    if report is None:
        return None
    if report.get("schema") != "crabc.aarch64-abi-probe/v1":
        raise RuntimeError(f"unexpected generated ABI probe report in {ABI_PROBE_REPORT}")
    if not isinstance(report.get("status"), str):
        raise RuntimeError(f"generated ABI probe report has no status: {ABI_PROBE_REPORT}")
    report["_path"] = str(ABI_PROBE_REPORT.relative_to(ROOT_DIR))
    return report


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


def runner_report_state(path: Path, expected_runner: str) -> dict[str, Any] | None:
    """Return a named report only when it is structurally identifiable."""

    report = read_json(path)
    if report is None:
        return None
    runner = report.get("runner", report.get("harness"))
    if runner != expected_runner:
        raise RuntimeError(f"unexpected report identity in {path}: {runner!r}")
    report["_path"] = str(path.relative_to(ROOT_DIR))
    return report


def static_pthread_tls_state() -> dict[str, Any] | None:
    """Return the static archive pthread/TLS lifecycle report with strict identity."""

    report = read_json(STATIC_PTHREAD_TLS_REPORT)
    if report is None:
        return None
    if report.get("schema") != 1 or report.get("runner") != "crabc-static-pthread-tls":
        raise RuntimeError(f"unexpected static pthread/TLS report identity in {STATIC_PTHREAD_TLS_REPORT}")
    report["_path"] = str(STATIC_PTHREAD_TLS_REPORT.relative_to(ROOT_DIR))
    return report


def loader_report_state() -> dict[str, Any] | None:
    """Return the synthetic loader report only when it has its runner identity."""

    report = read_json(LDSO_REPORT)
    if report is None:
        return None
    if report.get("schema") != 1 or report.get("runner") != "compat/ldso/run.py":
        raise RuntimeError(f"unexpected report identity in {LDSO_REPORT}")
    cases = report.get("cases")
    if report.get("result") == "pass" and not isinstance(cases, dict):
        raise RuntimeError(f"pass report has invalid cases in {LDSO_REPORT}")
    report["_path"] = str(LDSO_REPORT.relative_to(ROOT_DIR))
    return report


def corpus_report_state() -> dict[str, Any] | None:
    """Return the real-package corpus report only with its strict identity."""

    report = read_json(CORPUS_REPORT)
    if report is None:
        return None
    if report.get("schema_version") != 1 or report.get("runner") != "compat/corpus/run.py":
        raise RuntimeError(f"unexpected report identity in {CORPUS_REPORT}")
    cases = report.get("cases")
    if not isinstance(cases, dict):
        raise RuntimeError(f"report has invalid cases in {CORPUS_REPORT}")
    report["_path"] = str(CORPUS_REPORT.relative_to(ROOT_DIR))
    return report


def rust_std_report_state(path: Path) -> dict[str, Any] | None:
    """Return one raw-comparison Rust workload report with strict identity."""

    report = read_json(path)
    if report is None:
        return None
    if report.get("schema_version") != 1 or report.get("runner") != "compat/rust-std/run.py":
        raise RuntimeError(f"unexpected Rust workload report identity in {path}")
    comparison = report.get("comparison")
    if report.get("result") == "pass" and not isinstance(comparison, dict):
        raise RuntimeError(f"Rust pass report has invalid comparison in {path}")
    report["_path"] = str(path.relative_to(ROOT_DIR))
    return report


def lto_report_state() -> dict[str, Any] | None:
    """Return static/build-std LTO evidence only when all four lanes are named."""

    report = read_json(LTO_REPORT)
    if report is None:
        return None
    if report.get("schema_version") != 1 or report.get("runner") != "compat/lto/run.py":
        raise RuntimeError(f"unexpected report identity in {LTO_REPORT}")
    configurations = report.get("configurations")
    if not isinstance(configurations, dict) or not set("ABCD").issubset(configurations):
        raise RuntimeError(f"incomplete configuration matrix in {LTO_REPORT}")
    for key in "ABCD":
        configuration = configurations[key]
        if not isinstance(configuration, dict) or not isinstance(configuration.get("status"), str):
            raise RuntimeError(f"invalid configuration {key} in {LTO_REPORT}")
    report["_path"] = str(LTO_REPORT.relative_to(ROOT_DIR))
    return report


def native_facade_lto_report_state() -> dict[str, Any] | None:
    """Return candidate owned-sysroot evidence and its separate musl oracle."""

    report = read_json(NATIVE_FACADE_LTO_REPORT)
    if report is None:
        return None
    if report.get("schema_version") != 1 or report.get("runner") != "compat/lto/native_facade_lto.py":
        raise RuntimeError(f"unexpected report identity in {NATIVE_FACADE_LTO_REPORT}")
    lanes = report.get("lanes")
    if not isinstance(lanes, dict) or not {"control-o3", "fat-lto", "stock-std-fat"}.issubset(lanes):
        raise RuntimeError(f"incomplete lane set in {NATIVE_FACADE_LTO_REPORT}")
    for name in ("control-o3", "fat-lto", "stock-std-fat"):
        lane = lanes[name]
        if not isinstance(lane, dict) or not isinstance(lane.get("status"), str):
            raise RuntimeError(f"invalid lane {name} in {NATIVE_FACADE_LTO_REPORT}")
    candidate_groups = report.get("lane_groups")
    if isinstance(candidate_groups, dict) and candidate_groups.get("candidate_native_facade") != ["control-o3", "fat-lto"]:
        raise RuntimeError(f"unexpected candidate lane group in {NATIVE_FACADE_LTO_REPORT}")
    report["_path"] = str(NATIVE_FACADE_LTO_REPORT.relative_to(ROOT_DIR))
    return report


def lua_report_state() -> dict[str, Any] | None:
    """Return the owned-sysroot Lua gate only with its complete two-lane evidence."""

    report = read_json(LUA_REPORT)
    if report is None:
        return None
    if report.get("schema_version") != 1 or report.get("runner") != "crabc-lua-owned-sysroot":
        raise RuntimeError(f"unexpected Lua source-build report identity in {LUA_REPORT}")
    workloads = report.get("workloads")
    if not isinstance(workloads, dict):
        raise RuntimeError(f"Lua source-build report has invalid workloads in {LUA_REPORT}")
    for name in ("source", "bytecode"):
        if not isinstance(workloads.get(name), dict):
            raise RuntimeError(f"Lua source-build report lacks {name} comparison in {LUA_REPORT}")
    if report.get("result") == "pass":
        maps = workloads.get("candidate_maps")
        if not isinstance(maps, dict) or maps.get("status") != "passed":
            raise RuntimeError(f"Lua pass report lacks owned-runtime map isolation evidence in {LUA_REPORT}")
    report["_path"] = str(LUA_REPORT.relative_to(ROOT_DIR))
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
    abi_probe = abi_probe_state()
    environment = environment_state()
    ratchet = read_json(RATCHET_REPORT)
    libc_test = libc_test_states()
    differential = differential_state()
    os_test = runner_report_state(OS_TEST_REPORT, "pinned-os-test")
    pthread_stress = runner_report_state(PTHREAD_STRESS_REPORT, "crabc-pthread-stress")
    static_pthread_tls = static_pthread_tls_state()
    signal_process = runner_report_state(SIGNAL_PROCESS_REPORT, "crabc-signal-process")
    resolver_network = runner_report_state(RESOLVER_NETWORK_REPORT, "compat/resolver-network")
    loader_features = loader_feature_state()
    ldso = loader_report_state()
    corpus = corpus_report_state()
    rust_std = rust_std_report_state(RUST_STD_REPORT)
    rust_std_dependent = rust_std_report_state(RUST_STD_DEPENDENT_REPORT)
    lto = lto_report_state()
    native_facade_lto = native_facade_lto_report_state()
    lua = lua_report_state()

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    lines = [
        "# Compatibility Dashboard",
        "",
        "<!-- Generated by scripts/generate_compatibility_dashboard.py; do not edit manually. -->",
        "",
        f"Generated: `{generated_at}`",
        "",
        "This is a measurement dashboard for crabc's modern runtime profile "
        "(Linux AArch64 on Linux kernel versions 5.10 and newer), not a claim "
        "of complete historical musl or glibc compatibility. "
        "`exported`, `implemented`, and `verified` remain separate states.",
        "",
        "## Baseline",
        "",
    ]
    baseline_rows: list[tuple[object, object]] = [
        ("architecture", "AArch64 (`aarch64-unknown-linux-musl`)"),
        ("reference libc", f"musl {upstreams['musl']['version']}"),
        ("Docker platform", upstreams["environment"]["platform"]),
        ("Rust toolchain", upstreams["environment"]["rust_toolchain"]),
    ]
    if environment is None:
        baseline_rows.append(("tested source", "unrecorded; run an evidence command"))
    else:
        baseline_rows.extend(
            [
                ("tested source", f"`{environment['crabc_git_sha']}`"),
                (
                    "tested source tree",
                    "clean" if environment["crabc_git_dirty"] is False else "DIRTY (not final evidence)",
                ),
                ("environment report", f"`{environment['_path']}`"),
            ]
        )
    lines.extend(markdown_table(("field", "value"), baseline_rows))

    lines.extend(["", "## Evidence provenance", ""])
    if environment is None:
        lines.append("No source/artifact provenance report. Run an evidence command.")
    else:
        artifacts = environment["artifacts"]
        assert isinstance(artifacts, dict)
        artifact_rows = []
        for label, key in (
            ("`libc.so`", "libc_shared"),
            ("`libc.a`", "libc_static"),
            ("`libldso.so`", "ldso_shared"),
            ("public headers", "public_headers"),
            ("workspace lockfile", "workspace_lock"),
            ("oracle pins", "oracle_pins"),
        ):
            record = artifacts[key]
            assert isinstance(record, dict)
            artifact_rows.append((label, f"`{record['path']}`", provenance_value(record)))
        lines.extend(markdown_table(("input / artifact", "path", "SHA-256"), artifact_rows))
        lines.append(
            "The checked-in dashboard is an evidence-only child of the tested source commit above; "
            "it does not hash itself."
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

    lines.extend(["", "## Generated static/header ABI evidence", ""])
    if abi_probe is None:
        lines.append("No generated static/header ABI report. Run `./scripts/dev.sh abi-probe`.")
    else:
        coverage = abi_probe.get("header_compile_coverage", {})
        archive = abi_probe.get("static_archive_comparison", {})
        manifest = abi_probe.get("public_header_probe_manifest", {})
        declaration = manifest.get("declaration_probe", {}) if isinstance(manifest, dict) else {}
        lines.append(
            f"Generated pinned-musl public-header/static-archive evidence: "
            f"**{abi_probe.get('status', 'unknown')}**; report `{abi_probe['_path']}`."
        )
        lines.extend(
            markdown_table(
                ("surface", "status / count", "oracle scope"),
                [
                    (
                        "public-header declaration probes",
                        f"{coverage.get('compiled_count', 'unknown')}/"
                        f"{declaration.get('pinned_count', 'unknown')} compile-ok",
                        "generated from pinned musl header names",
                    ),
                    (
                        "layout/constant probes",
                        f"{abi_probe.get('summary', {}).get('by_status', {})}",
                        "candidate executable linked/run with pinned musl",
                    ),
                    (
                        "static archive symbols",
                        str(archive.get("status", "unknown")),
                        "nm classes; non-equal archives remain explicit triage",
                    ),
                ],
            )
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

    lines.extend(["", "## synthetic loader differential evidence", ""])
    if ldso is None:
        lines.append("No synthetic loader result. Run `./scripts/dev.sh ldso`.")
    else:
        cases = ldso.get("cases", {})
        if not isinstance(cases, dict):
            raise RuntimeError(f"invalid cases in {ldso['_path']}")
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

    lines.extend(["", "## real Alpine package corpus", ""])
    if corpus is None:
        lines.append("No real-package corpus result. Run `./scripts/dev.sh corpus`.")
    else:
        cases = corpus["cases"]
        passed_cases = sum(
            isinstance(case, dict) and case.get("result") == "pass" for case in cases.values()
        )
        lines.append(
            f"Pinned Alpine {corpus.get('alpine_release', 'unknown')} AArch64 package corpus: "
            f"**{'pass' if corpus.get('result') == 'pass' else 'FAIL'}** "
            f"({passed_cases}/{len(cases)} cases); report `{corpus['_path']}`."
        )
        lines.append(
            "Reference and candidate use the same kernel/image/non-libc DSOs; "
            "the candidate is entered as the package binary through an interpreter "
            "overlay, with raw stdout/stderr/status and no normalization."
        )
        stateful_cases = sum(
            isinstance(case, dict) and case.get("stateful") is True for case in cases.values()
        )
        lines.append(
            f"Stateful Tier B–D operations: **{stateful_cases}**; every package in those tiers "
            "is required by the manifest validator to have at least one."
        )
        if cases:
            lines.append("")
            lines.extend(
                markdown_table(
                    ("case", "tier", "package", "result", "status", "stdout", "stderr"),
                    [
                        (
                            name,
                            case.get("tier", "unknown"),
                            case.get("package", "unknown"),
                            case.get("result", "unknown"),
                            "match" if case.get("status_match") is True else "DIFF",
                            "match" if case.get("stdout_match") is True else "DIFF",
                            "match" if case.get("stderr_match") is True else "DIFF",
                        )
                        for name, case in sorted(cases.items())
                        if isinstance(case, dict)
                    ],
                )
            )

    lines.extend(["", "## Lua source-build owned-sysroot gate", ""])
    if lua is None:
        lines.append("No Lua owned-sysroot result. Run `./scripts/dev.sh lua`.")
    else:
        workloads = lua["workloads"]
        assert isinstance(workloads, dict)
        source = workloads["source"]
        bytecode = workloads["bytecode"]
        maps = workloads.get("candidate_maps")
        assert isinstance(source, dict) and isinstance(bytecode, dict)
        map_isolation = (
            isinstance(maps, dict)
            and maps.get("status") == "passed"
            and maps.get("no_musl_libc") is True
        )
        passed = (
            lua.get("result") == "pass"
            and lua.get("passed") is True
            and source.get("passed") is True
            and bytecode.get("passed") is True
            and map_isolation
        )
        manifest = lua.get("manifest")
        contents = manifest.get("contents") if isinstance(manifest, dict) else {}
        version = contents.get("lua", {}).get("version", "unknown") if isinstance(contents, dict) else "unknown"
        lines.append(
            f"Pinned Lua {version} shared-runtime owned-sysroot build: "
            f"**{'pass' if passed else 'FAIL'}**; report `{lua['_path']}`."
        )
        lines.append(
            "The interpreter is dynamically linked to source-built `liblua`; `luac` statically composes "
            "Lua-private compiler units but runs through the same crabc loader/libc. The candidate link "
            "uses the installed crabc headers, CRT objects, builtins archive, and canonical interpreter; "
            "the pinned musl runtime is retained only as the execution oracle."
        )
        lines.append("")
        lines.extend(
            markdown_table(
                ("lane", "status", "stdout", "stderr"),
                [
                    (
                        "Lua source",
                        "match" if source.get("status_match") is True else "DIFF",
                        "match" if source.get("stdout_match") is True else "DIFF",
                        "match" if source.get("stderr_match") is True else "DIFF",
                    ),
                    (
                        "luac bytecode",
                        "match" if bytecode.get("status_match") is True else "DIFF",
                        "match" if bytecode.get("stdout_match") is True else "DIFF",
                        "match" if bytecode.get("stderr_match") is True else "DIFF",
                    ),
                    (
                        "candidate maps",
                        "crabc-only" if map_isolation else "FAIL",
                        "n/a",
                        "n/a",
                    ),
                ],
            )
        )

    lines.extend(["", "## stock Rust std", ""])
    if rust_std is None:
        lines.append("No stock Rust std result. Run `./scripts/dev.sh rust-std`.")
    else:
        comparison = rust_std.get("comparison")
        if not isinstance(comparison, dict):
            raise RuntimeError(f"invalid comparison in {rust_std['_path']}")
        build = rust_std.get("build")
        if not isinstance(build, dict):
            raise RuntimeError(f"invalid build record in {rust_std['_path']}")
        passes = comparison.get("passed") is True
        lines.append(
            "Pinned stock Rust std (`-Z build-std`) musl-vs-crabc fixture: "
            f"**{'pass' if rust_std.get('result') == 'pass' and passes else 'FAIL'}** "
            f"(1/1 normal Rust workload); report `{rust_std['_path']}`."
        )
        lines.append(
            "The same dynamic AArch64 PIE runs as the kernel program under the pinned musl "
            "or crabc interpreter; its raw status, stdout, and stderr are compared without normalization."
        )
        lines.append("")
        lines.extend(
            markdown_table(
                ("metric", "result"),
                [
                    (
                        "stock std built with `-Z build-std`",
                        "pass" if build.get("returncode") == 0 else "FAIL",
                    ),
                    (
                        "dynamic musl ABI executable",
                        "pass"
                        if "libc.musl-aarch64.so.1" in str(build.get("dynamic_section", ""))
                        else "FAIL",
                    ),
                    ("status", "match" if comparison.get("status_match") is True else "DIFF"),
                    ("stdout", "match" if comparison.get("stdout_match") is True else "DIFF"),
                    ("stderr", "match" if comparison.get("stderr_match") is True else "DIFF"),
                ],
            )
        )

    lines.extend(["", "## Dependency-bearing Rust workload", ""])
    if rust_std_dependent is None:
        lines.append(
            "No dependency-bearing Rust workload result. Run `./scripts/dev.sh rust-std-dependent`."
        )
    else:
        comparison = rust_std_dependent.get("comparison")
        build = rust_std_dependent.get("build")
        if not isinstance(comparison, dict) or not isinstance(build, dict):
            raise RuntimeError(f"invalid dependent Rust evidence in {rust_std_dependent['_path']}")
        fixture = rust_std_dependent.get("fixture", {})
        fixture_name = fixture.get("package_name", "unknown") if isinstance(fixture, dict) else "unknown"
        passes = rust_std_dependent.get("result") == "pass" and comparison.get("passed") is True
        lines.append(
            "Pinned dependency-bearing stock Rust application (filesystem, async TCP, synchronization, "
            f"subprocess, and error path): **{'pass' if passes else 'FAIL'}**; "
            f"fixture `{fixture_name}`, report `{rust_std_dependent['_path']}`."
        )
        lines.extend(
            markdown_table(
                ("metric", "result"),
                [
                    ("locked dependency build", "pass" if build.get("returncode") == 0 else "FAIL"),
                    ("status", "match" if comparison.get("status_match") is True else "DIFF"),
                    ("stdout", "match" if comparison.get("stdout_match") is True else "DIFF"),
                    ("stderr", "match" if comparison.get("stderr_match") is True else "DIFF"),
                ],
            )
        )

    lines.extend(["", "## LTO research", ""])
    if lto is None:
        lines.append("No static/build-std LTO result. Run `./scripts/dev.sh lto`.")
    else:
        configurations = lto["configurations"]
        built = sum(
            configuration.get("status") == "built"
            for configuration in configurations.values()
            if isinstance(configuration, dict)
        )
        lines.append(
            "Static/build-std LTO evidence matrix: "
            f"**{lto.get('result', 'unknown')}** ({built}/4 built artifact/runtime lanes); "
            f"report `{lto['_path']}`."
        )
        lines.append(
            "`built` records an artifact and its run, not a whole-program claim. "
            "An `invalid` lane is retained as evidence when its link map disproves the requested boundary."
        )
        rows: list[tuple[object, ...]] = []
        for key in "ABCD":
            configuration = configurations[key]
            assert isinstance(configuration, dict)
            build = configuration.get("build")
            build = build if isinstance(build, dict) else {}
            artifact = build.get("artifact")
            artifact = artifact if isinstance(artifact, dict) else {}
            runtime = build.get("runtime")
            runtime = runtime if isinstance(runtime, dict) else {}
            claims = build.get("claims")
            claims = claims if isinstance(claims, dict) else {}
            provenance = build.get("lto_provenance")
            provenance = provenance if isinstance(provenance, dict) else {}
            if key == "B":
                boundary = (
                    "crabc archive selected"
                    if claims.get("static_crabc_linkage_proven") is True
                    else "crabc archive unproven"
                )
            elif key == "D":
                boundary = (
                    "cross-boundary LTO proven"
                    if claims.get("whole_program_lto_proven") is True
                    else "cross-boundary LTO unproven"
                )
            elif provenance:
                boundary = str(provenance.get("scope", "Rust/std evidence unavailable"))
            else:
                boundary = "static control"
            rows.append(
                (
                    key,
                    configuration.get("label", "unknown"),
                    configuration.get("status", "unknown"),
                    artifact.get("text_size_bytes", "n/a"),
                    artifact.get("stripped_file_size_bytes", "n/a"),
                    artifact.get("defined_global_symbol_count", "n/a"),
                    runtime.get("status", "n/a"),
                    boundary,
                )
            )
        lines.append("")
        lines.extend(
            markdown_table(
                ("case", "configuration", "status", ".text", "stripped ELF", "symbols", "run", "scope / boundary"),
                rows,
            )
        )

    lines.extend(["", "## native `crabc-rs` LTO proof", ""])
    if native_facade_lto is None:
        lines.append("No native-facade result. Run `./scripts/dev.sh lto-native-facade`.")
    else:
        lanes = native_facade_lto["lanes"]
        claims = native_facade_lto.get("claims")
        claims = claims if isinstance(claims, dict) else {}
        passed = native_facade_lto.get("result") == "complete" and native_facade_lto.get("status") == "built"
        lines.append(
            "Bounded native-facade O3/fat-LTO evidence: "
            f"**{'pass' if passed else 'FAIL'}**; report `{native_facade_lto['_path']}`."
        )
        lines.append(
            "The two candidate lanes link and run through the owned crabc sysroot; "
            "the stock-std musl comparison is a separately labelled oracle. "
            "This does not assert whole-program LTO or optimization inside dynamic `libc.so`."
        )
        rows = []
        for name in ("control-o3", "fat-lto", "stock-std-fat"):
            lane = lanes[name]
            assert isinstance(lane, dict)
            runtime = lane.get("runtime") if name != "stock-std-fat" else lane.get("runtime_comparison")
            runtime = runtime if isinstance(runtime, dict) else {}
            inspection = lane.get("inspection")
            inspection = inspection if isinstance(inspection, dict) else {}
            route = inspection.get("route", {})
            route = route if isinstance(route, dict) else {}
            rows.append(
                (
                    name,
                    lane.get("status", "unknown"),
                    runtime.get("status", "n/a"),
                    "yes" if route.get("witness_direct_getpid") is True else "no",
                )
            )
        lines.append("")
        lines.extend(markdown_table(("lane", "artifact", "runtime observation", "direct getpid witness"), rows))
        lines.append(
            "Claims: direct route="
            f"{claims.get('direct_syscall_route_proven') is True}; facade boundary eliminated="
            f"{claims.get('facade_boundary_eliminated') is True}; whole-program LTO="
            f"{claims.get('whole_program_lto_proven') is True}; dynamic-libc LTO="
            f"{claims.get('stock_std_lto_into_dynamic_libc_proven') is True}."
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

    lines.extend(["", "## standards and stress evidence", ""])
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

    if static_pthread_tls is None:
        lines.append("\nNo static libc.a pthread/TLS result. Run `./scripts/dev.sh static-pthread-tls`.")
    else:
        lines.append(
            f"\nStatic libc.a pthread/TLS lifecycle: "
            f"**{'pass' if static_pthread_tls.get('passed') is True else 'FAIL'}** "
            f"(owned crabc CRT/archive link and run, exact raw streams); "
            f"report `{static_pthread_tls['_path']}`."
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

    unmeasured_frontier = [
        "Static candidate ABI parity",
        "exhaustive header declaration/layout parity",
    ]
    if corpus is None:
        unmeasured_frontier.append("real Alpine corpus")
    if rust_std is None:
        unmeasured_frontier.append("stock Rust `std` compatibility")
    if rust_std_dependent is None:
        unmeasured_frontier.append("dependency-bearing Rust application")
    d_claims: dict[str, Any] = {}
    if lto is not None:
        d_configuration = lto["configurations"]["D"]
        assert isinstance(d_configuration, dict)
        d_build = d_configuration.get("build")
        if isinstance(d_build, dict):
            candidate_claims = d_build.get("claims")
            if isinstance(candidate_claims, dict):
                d_claims = candidate_claims
    if d_claims.get("whole_program_lto_proven") is not True:
        unmeasured_frontier.append("cross-boundary Rust/crabc LTO")

    lines.extend(
        [
            "",
            "## Unmeasured frontier",
            "",
            "The selected POSIX, signal/process, and resolver/network contracts above are not full "
            "standards conformance.",
            ", ".join(unmeasured_frontier) + " are not measured by this dashboard yet.",
            "The synthetic suite measures bounded loader contracts; it is not a claim that arbitrary "
            "Alpine DSO graphs are supported.",
            "",
        ]
    )
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
