#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for persistent allocator lifecycle.

The full profile requires persistent concurrency and lifecycle evidence,
structural audits, and early engine throughput. The correctness profile
requires the same functional evidence and production architecture checks while
deferring codegen optimization and throughput qualification. Its receipt cannot
qualify performance.

Evidence is one of four shapes:

* `native_tests`: `crabc-mimalloc/tests/native_*` integration targets, run
  together with their default-off audit and fault features. Every such
  target belongs to exactly one native evidence entry, so a new direct
  runtime witness cannot silently escape the evidence closure.
* `command`: an allocator-container command (`python3 <script> ...`). The
  one `{scratch}` placeholder names this run's fresh per-evidence directory.
* `receipt`: a runtime-launcher runner's revision-bound receipt, read and
  validated through the shared `compat/x86_64/native_shadow_receipt.py`
  reader: it must seal this exact checkout, record a canonical run, cite
  digest-matching raw logs, and contain at least one passing case of the
  named family with every case passing, the complete declared case and product
  sets, and the required workload parameters.
* `command: null`: evidence that exists only outside this launcher. It is
  declared missing here, so a gate that depends on it must name a blocker.

A gate passes only when it carries no reviewed blocker and every evidence
entry executed successfully on this run. Runnable evidence is always
executed; its pass never removes a blocker by itself.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness
import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated

sys.path.insert(0, str(harness.ROOT / "compat/x86_64"))
import native_shadow_receipt  # noqa: E402


CONTRACT = harness.ALLOCATOR_ROOT / "m5-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m5-gate"
GATE_IDS = (
    "m5.pointer-dispatch",
    "m5.remote-publication",
    "m5.generic-exit",
    "m5.abandon-reclaim-release",
    "m5.no-forbidden-scaffolding",
    "m5.libc-shadow",
    "m5.state-auditing",
    "m5.churn-soak",
    "m5.upstream-stress",
    "m5.codegen-performance",
)
NATIVE_TESTS = harness.ROOT / "crabc-mimalloc/tests"
NATIVE_TEST_PREFIX = "native_"
NATIVE_FEATURES = "native-runtime-test-audit,native-runtime-test-fault"
RUST_TARGET = "x86_64-unknown-linux-musl"
EVIDENCE_TIMEOUT_SECONDS = 3600
SCRATCH_PLACEHOLDER = "{scratch}"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m5-gate"
QUALIFICATION_PROFILES = ("full", "correctness")
CORRECTNESS_DEFERRED_GATE = "m5.codegen-performance"
CORRECTNESS_DEFERRED_EVIDENCE = ["codegen:hot-path-audit", "perf:engine-early-proof"]


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M5 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def native_test_targets(tests_root: Path = NATIVE_TESTS) -> set[str]:
    """Every direct native runtime integration target in the crate."""

    return {path.stem for path in tests_root.glob(f"{NATIVE_TEST_PREFIX}*.rs")}


def native_test_command(targets: Sequence[str]) -> list[str]:
    """One Cargo run over the named native targets with their audit seams."""

    command = [
        "cargo", "test", "--locked", "--target", RUST_TARGET, "-p", "crabc-mimalloc",
        "--no-default-features", "--features", NATIVE_FEATURES, "--no-fail-fast",
    ]
    for target in targets:
        command += ["--test", target]
    return command


def validate_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], native_targets: set[str]
) -> dict[str, Any]:
    """Validate gate identity, evidence honesty, and native-target closure."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M5 allocator gate contract")
    if contract.get("qualification_profiles") != {
        "full": {"deferred_evidence": []},
        "correctness": {"deferred_evidence": CORRECTNESS_DEFERRED_EVIDENCE},
    }:
        raise harness.HarnessError("M5 qualification profiles must defer only codegen optimization and early throughput evidence")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M5 allocator gate upstream identity mismatch")

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M5 allocator gate lacks an evidence registry")
    runnable: dict[str, list[str] | dict[str, Any]] = {}
    claimed: dict[str, str] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or not isinstance(record.get("scope"), str) or not record["scope"]:
            raise harness.HarnessError(f"M5 evidence {evidence_id} lacks a scope")
        shape = set(record) - {"scope"}
        if shape == {"native_tests"}:
            targets = _string_list(record["native_tests"], f"evidence {evidence_id} native tests")
            for target in targets:
                if target not in native_targets:
                    raise harness.HarnessError(f"M5 evidence {evidence_id} names an absent native target: {target}")
                if target in claimed:
                    raise harness.HarnessError(
                        f"M5 native target {target} is claimed by both {claimed[target]} and {evidence_id}"
                    )
                claimed[target] = evidence_id
            runnable[evidence_id] = native_test_command(targets)
        elif shape == {"command"}:
            command = record["command"]
            if command is None:
                continue
            command = _string_list(command, f"evidence {evidence_id} command")
            if len(command) < 2 or command[0] != "python3" or not (harness.ROOT / command[1]).is_file():
                raise harness.HarnessError(f"M5 evidence {evidence_id} names an absent runner")
            if sum(argument.count(SCRATCH_PLACEHOLDER) for argument in command) > 1:
                raise harness.HarnessError(f"M5 evidence {evidence_id} names more than one scratch directory")
            runnable[evidence_id] = command
        elif shape == {"receipt"}:
            check = record["receipt"]
            if (
                not isinstance(check, Mapping)
                or set(check) != {"runner", "case_prefix", "required_cases", "required_products", "parameters"}
                or not isinstance(check["runner"], str)
                or not native_shadow_receipt.RUNNER_RE.match(check["runner"])
                or not isinstance(check["case_prefix"], str)
                or not check["case_prefix"]
            ):
                raise harness.HarnessError(f"M5 evidence {evidence_id} names a malformed receipt check")
            for field in ("required_cases", "required_products"):
                _string_list(check[field], f"evidence {evidence_id} receipt {field}")
            if not isinstance(check["parameters"], Mapping) or not all(
                isinstance(key, str) and key and isinstance(value, str)
                for key, value in check["parameters"].items()
            ):
                raise harness.HarnessError(f"M5 evidence {evidence_id} names malformed receipt parameters")
            runnable[evidence_id] = dict(check)
        else:
            raise harness.HarnessError(
                f"M5 evidence {evidence_id} must record scope with exactly native_tests, command, or receipt"
            )
    # A native target may instead belong to another gate, which
    # must name that contract; it is then neither run nor claimed here.
    elsewhere = contract.get("native_tests_owned_elsewhere", {})
    if not isinstance(elsewhere, Mapping):
        raise harness.HarnessError("M5 native_tests_owned_elsewhere must map targets to their owning gate")
    for target, owner in elsewhere.items():
        if target not in native_targets:
            raise harness.HarnessError(f"M5 names an absent native target as owned elsewhere: {target}")
        if target in claimed:
            raise harness.HarnessError(f"M5 native target {target} is both claimed and owned elsewhere")
        if not isinstance(owner, str) or not (harness.ROOT / owner).is_file() or target not in (
            harness.ROOT / owner
        ).read_text():
            raise harness.HarnessError(f"M5 native target {target} names an owning gate that does not cite it")
    unclaimed = sorted(native_targets - set(claimed) - set(elsewhere))
    if unclaimed:
        raise harness.HarnessError(f"M5 evidence omits native integration targets: {unclaimed}")

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M5 allocator gate order or identity changed")
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M5 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M5 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M5 gate {gate_id} lacks an acceptance contract")
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M5 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M5 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M5 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "native_target_count": len(claimed),
        "runnable_evidence": dict(sorted(runnable.items())),
    }


def active_evidence(contract: Mapping[str, Any], qualification_profile: str) -> set[str]:
    """Select required producers without admitting deferred performance evidence."""

    if qualification_profile not in QUALIFICATION_PROFILES:
        raise harness.HarnessError(f"unsupported M5 qualification profile: {qualification_profile}")
    deferred = set(contract["qualification_profiles"][qualification_profile]["deferred_evidence"])
    return {name for record in contract["gates"] for name in record["evidence"]} - deferred


def gate_report(
    contract: Mapping[str, Any], summary: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]],
    *, qualification_profile: str = "full",
) -> dict[str, Any]:
    """Classify each gate from reviewed blockers and executed evidence."""

    if qualification_profile not in QUALIFICATION_PROFILES:
        raise harness.HarnessError(f"unsupported M5 qualification profile: {qualification_profile}")
    active = active_evidence(contract, qualification_profile)
    results = {name: result for name, result in results.items() if name in active}
    records: list[dict[str, Any]] = []
    for gate in contract["gates"]:
        observed = {entry: results[entry]["status"] for entry in gate["evidence"] if entry in results}
        missing = [entry for entry in gate["evidence"] if entry not in summary["runnable_evidence"]]
        deferred = qualification_profile == "correctness" and gate["id"] == CORRECTNESS_DEFERRED_GATE
        if deferred:
            status = "deferred"
        elif any(status != "passed" for status in observed.values()):
            status = "failed"
        elif gate["blocked_by"] or missing or len(observed) != len(gate["evidence"]):
            status = "blocked"
        else:
            status = "passed"
        records.append({
            "blocked_by": list(gate["blocked_by"]),
            "evidence": observed,
            "id": gate["id"],
            "missing_evidence": missing,
            "status": status,
        })
    unmet = [record["id"] for record in records if record["status"] not in {"passed", "deferred"}]
    return {
        "contract": harness.relative(CONTRACT),
        "evidence": {key: dict(value) for key, value in sorted(results.items())},
        "gates": records,
        "overall_status": "passed" if not unmet else "unmet",
        "qualification_profile": qualification_profile,
        "performance_qualified": qualification_profile == "full" and not unmet
                                 and [record["id"] for record in records] == list(GATE_IDS),
        "deferred_gate_ids": [record["id"] for record in records
                              if qualification_profile == "correctness" and record["id"] == CORRECTNESS_DEFERRED_GATE],
        "unmet_required": unmet,
    }


def report_provenance(report: Mapping[str, Any]) -> dict[str, Any]:
    """Bind executed evidence to the checkout and its retained raw logs."""

    return {
        "git": engine.git_provenance(),
        "seal": {**integrated.source_seal(), "gate": engine.file_record(Path(__file__)),
                 "contract": engine.file_record(CONTRACT)},
        "receipts": {
            name: engine.file_record(native_shadow_receipt.receipt_directory(harness.ROOT, record["receipt"]["runner"]) / "receipt.json")
            for name, record in report["evidence"].items()
            if "receipt" in record and record["status"] == "passed"
        },
        "evidence": {name: engine.file_record(harness.ROOT / record["log"])
                     for name, record in report["evidence"].items()},
    }


def read_report(path: Path | None = None, *, profile: str = "full") -> dict[str, Any]:
    """Read complete current functional evidence for the selected profile.

    Full qualification also replays the physical codegen audit. Correctness
    defers that audit and throughput without qualifying either as performance.
    """

    if profile not in QUALIFICATION_PROFILES:
        raise harness.HarnessError(f"unsupported M5 qualification profile: {profile}")
    artifacts = ARTIFACTS if profile == "full" else ARTIFACTS.with_name("m5-correctness-gate")
    path = artifacts / "report.json" if path is None else Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.resolve() != (artifacts / "report.json").resolve():
            raise harness.HarnessError("M5 report is absent or outside its profile directory")
        report = harness.read_json(path)
        import x86_64_m9_gate as audit_reader

        unmet = audit_reader.correctness_evidence_unmet(
            "m5", report, artifacts, None, qualification_profile=profile)
        if unmet:
            raise harness.HarnessError("M5 report is unmet: " + "; ".join(unmet))
        if profile == "correctness":
            return report
        import codegen_audit_x86_64 as codegen

        audit_path = codegen.REPORT_ROOT / "m5-gate.json"
        audit = harness.read_json(audit_path)
        unmet = audit_reader.codegen_unmet(audit, [scenario.name for scenario in codegen.SCENARIOS])
        inputs = audit["provenance"]["inputs"]
        source = dict(inputs, mimalloc={key: inputs["mimalloc"][key] for key in ("version", "tag", "revision")}
                      | {"archive_sha256": inputs["mimalloc"]["archive"]["sha256"]})
        products = audit_path.with_suffix(".artifacts")
        product_identity = {key: engine.sha256_file(products / name) for key, name in {
            "pinned_c_executable": "engine-fixture-pinned-c",
            "rust_engine_executable": "engine-fixture-rust-engine",
            "shared_fixture_object": "engine-fixture-c.o",
            "rust_engine_static_library": "libcrabc_allocator_engine_rust_backend.a",
        }.items()}
        unmet.extend(audit_reader.physical_codegen_unmet(audit_path, audit, codegen, {
            "identity": {"source": source, "configuration": {"tools": audit["provenance"]["tools"]}},
            "product_identity": product_identity,
        }))
        if unmet:
            raise harness.HarnessError("M5 structural audit is unmet: " + "; ".join(unmet))
        return report
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise harness.HarnessError(f"M5 report lacks current physical evidence: {error}") from error


def check_receipt(check: Mapping[str, Any], root: Path = harness.ROOT) -> tuple[bool, str]:
    """Validate one runner receipt; the message names its seal or its defect."""

    try:
        receipt = native_shadow_receipt.read_receipt(root, check["runner"], case_prefix=check["case_prefix"])
    except native_shadow_receipt.ReceiptError as error:
        return False, str(error)
    for field, observed in (("required_cases", receipt.case_ids()), ("required_products", receipt.products)):
        missing = sorted(set(check.get(field, [])) - set(observed))
        if missing:
            return False, f"{check['runner']}: receipt lacks {field}: {missing}"
    if any(receipt.parameters.get(key) != value for key, value in check.get("parameters", {}).items()):
        return False, f"{check['runner']}: receipt parameters differ from the required workload"
    cases = receipt.case_ids(check["case_prefix"])
    return True, (
        f"{check['runner']}: {len(cases)} passing {check['case_prefix']!r} cases of "
        f"{len(receipt.cases)} at {receipt.source['revision']} "
        f"(worktree {receipt.source['worktree_sha256']}); {harness.relative(receipt.path)}\n"
        + "".join(f"  {case}\n" for case in cases)
    )


def receipt_evidence_unmet(
    report: Mapping[str, Any], runnable: Mapping[str, Any], root: Path = harness.ROOT,
) -> list[str]:
    """Reopen retained runner evidence instead of trusting its summary log."""

    checks = {name: check for name, check in runnable.items() if isinstance(check, Mapping)}
    try:
        identities = report["provenance"]["receipts"]
        if not isinstance(identities, Mapping) or set(identities) != set(checks):
            return ["M5 report lacks the original runner receipt identities"]
        for name, check in checks.items():
            if report["evidence"][name].get("receipt") != check:
                return [f"M5 evidence {name} differs from its required receipt check"]
            passed, message = check_receipt(check, root)
            if not passed:
                return [f"M5 evidence {name} lacks original evidence: {message}"]
            path = native_shadow_receipt.receipt_directory(root, check["runner"]) / "receipt.json"
            if identities[name] != engine.file_record(path):
                return [f"M5 evidence {name} differs from its original runner receipt"]
    except (KeyError, TypeError, ValueError, OSError) as error:
        return [f"M5 original runner evidence is unreadable: {error}"]
    return []


def run_evidence(runnable: Mapping[str, Any], artifacts: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for evidence_id, command in runnable.items():
        name = evidence_id.replace(":", "-")
        log = artifacts / f"{name}.log"
        if isinstance(command, Mapping):
            passed, message = check_receipt(command)
            log.write_text(message + "\n")
            results[evidence_id] = {
                "log": harness.relative(log),
                "receipt": dict(command),
                "status": "passed" if passed else "failed",
            }
            continue
        # Evidence that refuses to overwrite its own receipt gets a directory
        # that this gate run alone owns.
        scratch = artifacts / name
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        command = [argument.replace(SCRATCH_PLACEHOLDER, str(scratch)) for argument in command]
        record = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        results[evidence_id] = {
            "command": list(command),
            "log": harness.relative(log),
            "status": "passed" if record["status"] == 0 else "failed",
        }
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
        help="validate the contract and native-target closure without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS,
        help="execute and classify only the evidence of one gate")
    parser.add_argument("--qualification-profile", choices=QUALIFICATION_PROFILES, default="full",
        help="correctness requires functional evidence and defers codegen optimization and throughput")
    arguments = parser.parse_args(argv)
    contract = harness.read_json(CONTRACT)
    summary = validate_contract(contract, harness.load_pin(), native_test_targets())
    if arguments.check:
        print(
            f"M5 gate contract valid: {summary['native_target_count']} native targets in "
            f"{len(summary['gate_ids'])} gates; {len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    artifacts = ARTIFACTS if arguments.qualification_profile == "full" else ARTIFACTS.with_name("m5-correctness-gate")
    artifacts.mkdir(parents=True, exist_ok=True)
    selected = contract
    runnable = summary["runnable_evidence"]
    if arguments.gate is not None:
        selected = dict(contract, gates=[gate for gate in contract["gates"] if gate["id"] == arguments.gate])
        wanted = set(selected["gates"][0]["evidence"])
        runnable = {key: value for key, value in runnable.items() if key in wanted}
    active = active_evidence(selected, arguments.qualification_profile)
    runnable = {key: value for key, value in runnable.items() if key in active}
    report = gate_report(selected, summary, run_evidence(runnable, artifacts),
                         qualification_profile=arguments.qualification_profile)
    report["provenance"] = report_provenance(report)
    harness.write_json(artifacts / "report.json", report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
    if report["overall_status"] != "passed":
        print(
            f"M5 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(artifacts / 'report.json')}",
            file=sys.stderr,
        )
        return 1
    print("M5 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
