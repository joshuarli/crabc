#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for allocator Milestone 10.

M10 is the "isolated qualified x86 default switch; C mimalloc absent from
target production dependencies and artifacts, exact C v3.5.0 retained only as
oracle, and required native commands rerun at the promotion revision"
(plan.md Milestones). The switch itself is one line,
``DEFAULT_ALLOCATOR_BACKEND`` in ``scripts/build_x86_64_owned_sysroot.py``,
which both product builders use; this gate never edits it.

``--build-audit`` builds the production-shaped ``--allocator-backend native``
static and dynamic products and audits them for any C mimalloc: archive
members and symbols of ``libc.a``, static and dynamic symbols of ``libc.so``,
installed headers, every provenance file, and the resolved Cargo graph of
the selected features (no ``libmimalloc-sys``). The audit report is sealed
to the Git HEAD it built.

``--check`` builds nothing. It names every unmet condition:

* ``m10.prior-milestones``: M0 (``run.py --check``) and the retained M1-M9
  reports all passed;
* ``m10.promotion-gates``: a ``performance.release`` receipt that its own
  validator accepts;
* ``m10.native-artifacts``: a passing ``--build-audit`` report for this HEAD;
* ``m10.oracle-retained``: the exact pinned C v3.5.0 archive, source map and
  oracle harness remain in the checkout;
* ``m10.promotion-rerun``: the required native commands rerun at the
  promotion revision, which exists only once the switch is committed;
* ``m10.switch``: the default is still ``accepted-c``; the report records
  every line the switch changes or that selects ``accepted-c`` by name.
  A default switched before every other condition passes is an error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness


ROOT = harness.ROOT
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m10-gate"
AUDIT_REPORT = ARTIFACTS / "native-artifact-audit.json"
PRODUCTS = ROOT / ".work/allocator-x86_64/m10-native"
BUILDERS = {"static": ROOT / "scripts/build_x86_64_owned_sysroot.py",
            "dynamic": ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"}
DEFAULT_LINE = re.compile(r'^DEFAULT_ALLOCATOR_BACKEND = "([a-z-]+)"$', re.MULTILINE)
PRODUCTION_BACKEND = "native"
CURRENT_DEFAULT = "accepted-c"
C_SYMBOL = re.compile(r"^_?mi_[A-Za-z0-9_]*$")
C_MEMBER = re.compile(r"^(?!.*\.rcgu\.o$)(?:[0-9a-f]+-static\.o|.*mimalloc.*)$")
C_PROVENANCE_TOKENS = ("libmimalloc", "c_src/mimalloc", "/mimalloc.h", "pinned-mimalloc", "mimalloc-3.5.0/")
C_DEPENDENCY = "libmimalloc-sys"
PRIOR_REPORTS = {
    "M1": harness.REPORT_ROOT / "x86_64/m1-foundations-latest.json",
    "M2": harness.REPORT_ROOT / "x86_64/m2-memory-substrate-latest.json",
    "M3": harness.REPORT_ROOT / "x86_64/m3-local-engine-latest.json",
    "M4": harness.ARTIFACT_ROOT / "x86_64/m4-gate/report.json",
    "M5": harness.ARTIFACT_ROOT / "x86_64/m5-gate/report.json",
    "M6": harness.ARTIFACT_ROOT / "x86_64/m6-gate/report.json",
    "M7": harness.ARTIFACT_ROOT / "x86_64/m7-gate/report.json",
    "M9": harness.ARTIFACT_ROOT / "x86_64/m9-gate/report.json",
}
ORACLE_INPUTS = ("compat/upstreams.toml", "crabc-mimalloc/UPSTREAM.md", "compat/allocator/x86_64-source-map-v3.5.0.json",
                 "compat/allocator/perf-x86_64/engine-c-backend.c")


def _condition(identifier: str, unmet: Sequence[str], detail: str) -> dict[str, Any]:
    return {"id": identifier, "met": not unmet, "detail": list(unmet) if unmet else detail}


def git_head() -> dict[str, Any]:
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True)
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True, text=True)
    return {"head": head.stdout.strip(), "clean": head.returncode == 0 and status.returncode == 0 and not status.stdout.strip()}


# ---- native artifact audit ------------------------------------------------------


def _lines(command: Sequence[str]) -> list[str]:
    completed = subprocess.run(list(map(str, command)), capture_output=True, text=True)
    if completed.returncode != 0:
        raise harness.HarnessError(f"{' '.join(map(str, command))} failed: {completed.stderr.strip()}")
    return completed.stdout.splitlines()


def symbol_names(nm: str, path: Path, *flags: str) -> set[str]:
    return {line.split()[-1] for line in _lines([nm, *flags, path])
            if len(line.split()) >= 2 and not line.endswith(":")}


def audit_product(product: Path, *, ar: str, nm: str, cargo_packages: Sequence[str]) -> list[str]:
    """Every trace of C mimalloc in one installed product; empty when it has none."""

    unmet: list[str] = []
    metadata = product / "share/crabc"
    manifest = json.loads((metadata / "manifest.json").read_text(encoding="utf-8"))
    shared = metadata / "libc-shared.provenance.json"
    backend = manifest.get("allocator_backend")
    if backend is None and shared.is_file():
        backend = json.loads(shared.read_text(encoding="utf-8")).get("allocator_backend")
    if backend != PRODUCTION_BACKEND:
        unmet.append(f"{product.name}: product backend is {backend!r}, not {PRODUCTION_BACKEND!r}")
    static, dynamic = product / "usr/lib/libc.a", product / "usr/lib/libc.so"
    if static.is_file():
        members = _lines([ar, "t", static])
        unmet.extend(f"{product.name}: libc.a member {member} is a C mimalloc object"
                     for member in members if C_MEMBER.search(member))
        names = symbol_names(nm, static)
        unmet.extend(f"{product.name}: libc.a names C mimalloc symbol {name}" for name in sorted(names)
                     if C_SYMBOL.match(name))
    if dynamic.is_file():
        names = symbol_names(nm, dynamic) | symbol_names(nm, dynamic, "--dynamic")
        unmet.extend(f"{product.name}: libc.so names C mimalloc symbol {name}" for name in sorted(names)
                     if C_SYMBOL.match(name))
    if not static.is_file() and not dynamic.is_file():
        unmet.append(f"{product.name}: product installs neither libc.a nor libc.so")
    unmet.extend(f"{product.name}: installs C mimalloc header {path.relative_to(product)}"
                 for path in sorted((product / "usr/include").rglob("mimalloc*")))
    for path in sorted(metadata.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        found = [token for token in C_PROVENANCE_TOKENS if token in text]
        if found:
            unmet.append(f"{product.name}: provenance {path.name} names C mimalloc ({', '.join(found)})")
    for name in ("libc-static.provenance.json", "libc-shared.provenance.json"):
        path = metadata / name
        if path.is_file():
            graph = json.loads(path.read_text(encoding="utf-8")).get("dependency_graph", {})
            recorded = graph.get("packages", [])
            if not recorded:
                unmet.append(f"{product.name}: {name} records no resolved dependency graph")
            unmet.extend(f"{product.name}: recorded dependency graph selects {package}"
                         for package in recorded if package.startswith(C_DEPENDENCY))
    unmet.extend(f"resolved Cargo graph of the native features selects {package}"
                 for package in cargo_packages if package.startswith(C_DEPENDENCY))
    return unmet


def build_and_audit() -> dict[str, Any]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_x86_64_owned_sysroot as common

    head = git_head()
    tools = common.resolve_pinned_producer_tools()
    ar, nm = common.producer_tool_path(tools, "llvm-ar"), common.producer_tool_path(tools, "llvm-nm")
    PRODUCTS.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {}
    unmet: list[str] = []
    for kind, builder in BUILDERS.items():
        output = PRODUCTS / kind
        for stale in (output, output.parent / (output.name + ".build")):
            if stale.exists():
                subprocess.run(["rm", "-rf", str(stale)], check=True)
        completed = subprocess.run(["python3", str(builder), "--output", str(output),
                                    "--allocator-backend", PRODUCTION_BACKEND], cwd=ROOT, capture_output=True, text=True)
        log = ARTIFACTS / f"build-{kind}.log"
        log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        if completed.returncode != 0:
            unmet.append(f"{kind} native product build failed; see {harness.relative(log)}")
            results[kind] = {"built": False}
            continue
        features = "x86-owned-static-native-shadow" if kind == "static" else "x86-owned-dynamic-native-shadow"
        try:
            graph = common.allocator_dependency_graph([tools["rustup"]["path"], "run", common.PINNED_TOOLCHAIN, "cargo"],
                                                      features, "native-shadow", common.deterministic_environment())
        except common.BuildError as error:
            graph = {"packages": [], "error": str(error)}
            unmet.append(f"{kind}: resolved Cargo graph refused: {error}")
        product_unmet = audit_product(output, ar=ar, nm=nm, cargo_packages=graph.get("packages", []))
        unmet.extend(product_unmet)
        results[kind] = {"built": True, "path": harness.relative(output), "unmet": product_unmet,
                         "cargo_packages": graph.get("packages", [])}
    return {"schema": "crabc-mimalloc-x86_64-m10-native-artifact-audit/v1", "git": head,
            "products": results, "unmet": unmet, "passed": not unmet and head["clean"]}


# ---- check ------------------------------------------------------------------------


def report_passed(path: Path) -> str | None:
    """Why a retained milestone report is not a pass, or None when it passed."""

    if not path.is_file():
        return f"no retained report ({harness.relative(path)})"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return f"unreadable report: {error}"
    status = report.get("overall_status", report.get("status"))
    return None if status in {"passed", "complete"} else f"report status is {status!r}"


def prior_milestones(m0: Mapping[str, Any]) -> dict[str, Any]:
    unmet = [] if m0.get("status") == 0 else [f"M0: run.py --check exited {m0.get('status')}"]
    for milestone, path in PRIOR_REPORTS.items():
        reason = report_passed(path)
        if reason:
            unmet.append(f"{milestone}: {reason}")
    unmet.append("M8: allocator M8 has no gate in this launcher")
    return _condition("m10.prior-milestones", unmet, "M0-M9 passed")


def promotion_gates(receipt: Path | None) -> dict[str, Any]:
    if receipt is None:
        return _condition("m10.promotion-gates", ["no performance.release receipt supplied (--performance-receipt)"], "")
    sys.path.insert(0, str(ROOT / "compat/x86_64"))
    import performance_release_gate as release

    try:
        release.validate_receipt(ROOT, receipt)
    except Exception as error:  # noqa: BLE001 - the validator's refusal is the detail
        return _condition("m10.promotion-gates", [f"{type(error).__name__}: {error}"], "")
    return _condition("m10.promotion-gates", [], f"{harness.relative(receipt)} passes performance.release")


def native_artifacts(head: Mapping[str, Any], path: Path = AUDIT_REPORT) -> dict[str, Any]:
    if not path.is_file():
        return _condition("m10.native-artifacts", ["no native artifact audit (allocator-m10 --build-audit)"], "")
    report = json.loads(path.read_text(encoding="utf-8"))
    unmet = list(report.get("unmet", []))
    if report.get("git", {}).get("head") != head.get("head"):
        unmet.append(f"native artifact audit is for {report.get('git', {}).get('head')}, not HEAD {head.get('head')}")
    if not report.get("git", {}).get("clean"):
        unmet.append("native artifact audit was built from a dirty tree")
    return _condition("m10.native-artifacts", unmet, "static and dynamic native products contain no C mimalloc")


def oracle_retained() -> dict[str, Any]:
    unmet = [f"oracle input {item} is absent" for item in ORACLE_INPUTS if not (ROOT / item).is_file()]
    pin = harness.load_pin()
    if pin.get("version") != "3.5.0":
        unmet.append(f"the pinned C oracle is {pin.get('version')}, not 3.5.0")
    return _condition("m10.oracle-retained", unmet, "exact C v3.5.0 pin, source map and C oracle backend retained")


def switch_record() -> dict[str, Any]:
    """The one default line and every line that selects the C backend by name."""

    builder = BUILDERS["static"]
    match = DEFAULT_LINE.search(builder.read_text(encoding="utf-8"))
    default = match.group(1) if match else None
    selections = []
    for base in ("scripts", "compat/x86_64"):
        for path in sorted((ROOT / base).rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if '"accepted-c"' in line and "ALLOCATOR_BACKENDS" not in line:
                    selections.append(f"{path.relative_to(ROOT).as_posix()}:{number}: {line.strip()}")
    return {"default": default, "default_line": f"{builder.relative_to(ROOT).as_posix()}: DEFAULT_ALLOCATOR_BACKEND",
            "would_change": [f'DEFAULT_ALLOCATOR_BACKEND = "{CURRENT_DEFAULT}" -> "{PRODUCTION_BACKEND}"'],
            "accepted_c_selections": selections}


def switch_condition(record: Mapping[str, Any], others_met: bool) -> dict[str, Any]:
    if record["default"] not in {CURRENT_DEFAULT, PRODUCTION_BACKEND}:
        raise harness.HarnessError(f"the default allocator backend line is unreadable: {record['default']!r}")
    if record["default"] == PRODUCTION_BACKEND and not others_met:
        raise harness.HarnessError("the default was switched to native before every M10 condition passed")
    if record["default"] == CURRENT_DEFAULT:
        return _condition("m10.switch", [f"default is {CURRENT_DEFAULT}; the switch changes {record['default_line']}",
                                         f"{len(record['accepted_c_selections'])} lines select accepted-c by name "
                                         "and are recorded for review"], "")
    return _condition("m10.switch", [], "default is native")


def evaluate(*, m0: Mapping[str, Any], receipt: Path | None, head: Mapping[str, Any]) -> dict[str, Any]:
    conditions = [prior_milestones(m0), promotion_gates(receipt), native_artifacts(head), oracle_retained(),
                  _condition("m10.promotion-rerun", ["the required native commands have not been rerun at a "
                                                     "promotion revision (it exists only once the switch is committed)"], "")]
    record = switch_record()
    conditions.append(switch_condition(record, all(row["met"] for row in conditions)))
    unmet = [row["id"] for row in conditions if not row["met"]]
    return {"schema": "crabc-mimalloc-x86_64-m10-gate/v1", "git": dict(head), "conditions": conditions,
            "switch": record, "unmet": unmet, "overall_status": "passed" if not unmet else "unmet"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="name every unmet M10 condition; builds nothing")
    mode.add_argument("--build-audit", action="store_true", help="build and audit the native static and dynamic products")
    parser.add_argument("--performance-receipt", type=Path, default=None)
    arguments = parser.parse_args(argv)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    if arguments.build_audit:
        harness.require_native_x86_64()
        report = build_and_audit()
        harness.write_json(AUDIT_REPORT, report)
        for kind, result in report["products"].items():
            print(f"{kind}: {'clean' if result.get('built') and not result['unmet'] else 'unmet'}")
        for item in report["unmet"]:
            print(f"  - {item}")
        print(f"native artifact audit: {'passed' if report['passed'] else 'unmet'} ({harness.relative(AUDIT_REPORT)})")
        return 0 if report["passed"] else 1
    m0 = harness.command_record(["python3", "compat/allocator/run.py", "--check", "--architecture", "x86_64",
                                 "--offline"], cwd=ROOT, timeout_seconds=900)
    result = evaluate(m0={"status": m0["status"]}, receipt=arguments.performance_receipt, head=git_head())
    harness.write_json(ARTIFACTS / "report.json", result)
    for row in result["conditions"]:
        print(f"{row['id']}: {'met' if row['met'] else 'unmet'}")
        if not row["met"]:
            for item in row["detail"]:
                print(f"  - {item}")
    print(f"M10 {result['overall_status']}; switch record in {harness.relative(ARTIFACTS / 'report.json')}")
    return 0 if result["overall_status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
