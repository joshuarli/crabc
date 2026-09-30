"""Replay the original native foundation, substrate, and local-engine receipts.

Readers use the producing checkout's contract, clean source identity, native
image, artifact records and source trace parsers. A retained completion label
cannot override an open source condition or a missing physical observation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Mapping

import run as harness


def require(value: bool, detail: str) -> None:
    if not value:
        raise harness.HarnessError(detail)


def authenticate_source(report: Mapping[str, Any], state: Mapping[str, Any], attest: Any) -> None:
    require(report.get("source") == attest(state, state), "receipt does not belong to current clean source")
    execution = harness.require_native_x86_64(require_image_identity=True)
    harness.validate_native_execution_provenance(report.get("native_execution_provenance"),
                                                expected_image_id=execution["image_id"])


def authenticate_artifacts(value: Any, pinned: Path) -> int:
    """Reread declared file records, using pinned-source records for upstream files."""
    count = 0
    if isinstance(value, Mapping):
        if {"path", "bytes", "sha256"} <= value.keys():
            name = value["path"]
            require(isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts,
                    "artifact path escapes its source or checkout")
            source_file = name.startswith(("include/mimalloc", "src/", "test/"))
            path = (pinned if source_file else harness.ROOT) / name
            require(not path.is_symlink(), f"artifact is a symlink: {name}")
            actual = (harness.source_file_records(pinned, [name])[0] if source_file
                      else harness.artifact_record(path))
            require(all(actual[key] == value[key] for key in ("path", "bytes", "sha256")),
                    f"artifact changed: {name}")
            count += 1
        for child in value.values():
            count += authenticate_artifacts(child, pinned)
    elif isinstance(value, list):
        for child in value:
            count += authenticate_artifacts(child, pinned)
    return count


def focused_commands(report: Mapping[str, Any], summary: Mapping[str, Any]) -> dict[tuple[str, ...], list[dict[str, Any]]]:
    require(all(component.get("native_status") == harness.M1_X86_64_FOUNDATIONS_COMPONENT_STATUS
                and component.get("remaining_conditions") == [] for component in summary["components"]),
            "foundation source component remains incomplete")
    expected = {(component["id"], check["id"]): check for component in summary["components"]
                for check in component["checks"]}
    require([c["id"] for c in report["components"]] == [c["id"] for c in summary["components"]],
            "receipt component roster differs from the source contract")
    seen = set()
    commands: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for component in report["components"]:
        require(component["status"] == "complete" and not component["remaining_conditions"],
                f"component remains incomplete: {component['id']}")
        for check in component["executed_checks"]:
            key = (component["id"], check["id"])
            require(key in expected and key not in seen, "focused check is unknown or duplicated")
            declared = expected[key]
            require(check["component"] == key[0] and check["target"] == declared["target"]
                    and check["passed_test_count"] == declared["expected_passed_test_count"],
                    f"focused check differs from source contract: {key}")
            command = tuple(check["command"])
            require(command and Path(command[0]).is_absolute()
                    and Path(command[0]).resolve().is_relative_to(harness.ROOT / ".work")
                    and not Path(command[0]).is_symlink(), "focused program is outside owned artifacts")
            commands.setdefault(command, []).append(check)
            seen.add(key)
    require(seen == set(expected), "receipt lacks a required focused check")
    return commands


def execute(command: list[str] | tuple[str, ...], timeout: int) -> dict[str, Any]:
    result = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=timeout)
    destination = os.environ.get("CRABC_RECEIPT_REPLAY_OUTPUT")
    if destination:
        root = Path(destination)
        root.mkdir(parents=True, exist_ok=True)
        harness.write_json(root / f"command-{len(list(root.glob('command-*.json'))):03}.json", result)
    harness.require_success(result, "retained source receipt replay")
    return result


def output(record: Mapping[str, Any]) -> str:
    return str(record["stdout"]) + "\n" + str(record["stderr"])


def read_m1_components(path: Path | None = None) -> dict[str, Any]:
    report = harness.read_json(path or harness.M1_X86_64_FOUNDATIONS_REPORT)
    contract = harness.read_json(harness.M1_X86_64_FOUNDATIONS_CONTRACT)
    pin = harness.load_pin()
    summary = harness.validate_x86_64_m1_foundations_contract(contract, pin)
    require(report["contract"] == harness.m1_foundations_contract_record(
        contract, pin, contract_path=harness.M1_X86_64_FOUNDATIONS_CONTRACT), "foundation contract changed")
    authenticate_source(report, harness.m1_foundations_source_state(), harness.m1_foundations_source_attestation)
    require(report["milestone"]["status"] == "complete", "foundation receipt remains incomplete")
    commands = focused_commands(report, summary)
    latest = harness.read_json(harness.X86_64_ORACLE_REPORT_ROOT / "latest.json")
    with harness.temporary_directory(prefix="foundation-receipt-reader-") as scratch:
        pinned = harness.safe_extract(harness.fetch_archive(pin, True), Path(scratch) / "source", pin["archive_root"])
        authenticate_artifacts(report, pinned)
        authenticate_artifacts(latest["c_oracle"], pinned)
        authenticate_artifacts(latest["x86_64_normal_engine_artifact"], pinned)
    timeout = summary["execution"]["timeout_seconds"]
    replayed = {}
    for argv, checks in commands.items():
        program = {"path": Path(argv[0]), "execution": summary["execution"]}
        names = harness._m1_foundations_test_names(program, timeout_seconds=timeout)
        selected = {check["target"] for check in checks}
        if len(checks) == 1:
            expected = harness._m1_foundations_program_check_command(program, checks[0]["target"], nocapture=True)
        else:
            expected = [argv[0], f"--test-threads={summary['execution']['test_threads']}",
                        *(entry for name in sorted(names - selected) for entry in ("--skip", name))]
        require(list(argv) == expected and selected <= names, "focused replay command differs from its source producer")
        result = execute(argv, timeout)
        require(harness.parse_rust_test_count(output(result)) == sum(check["passed_test_count"] for check in checks),
                "focused replay test count differs")
        for check in checks:
            replayed[check["id"]] = result
    binary = next(iter(commands))[0]
    full = execute([binary, "--test-threads=1", "--nocapture"], 300)
    require(harness.parse_rust_test_count(output(full)) == latest["rust_direct_engine"]["passed_test_count"],
            "full unit replay differs from the original oracle")
    def c_trace(directory: Path, name: str) -> str:
        return execute([str(directory / name)], timeout)["stdout"]
    bits = report["shared_evidence"]["x86_64_bit_arithmetic_c_rust_trace"]
    c_bits = harness.parse_m1_bit_arithmetic_trace(c_trace(harness.M1_X86_64_BITS_TRACE_ARTIFACT_ROOT,
        "m1-bits-c-rust-trace-probe"), source="retained C")
    rust_bits = harness.parse_m1_bit_arithmetic_trace(output(replayed["bit-arithmetic-c-rust-differential"]), source="retained Rust")
    require(c_bits == rust_bits == (harness.ROOT / bits["c_raw_output"]["path"]).read_text().splitlines()
            == (harness.ROOT / bits["rust_raw_output"]["path"]).read_text().splitlines(), "bit arithmetic observation changed")
    harness.compare_m1_raw_primitive_trace(
        harness.parse_m1_raw_primitive_trace(c_trace(harness.M1_X86_64_RAW_PRIMITIVE_TRACE_ARTIFACT_ROOT,
                                                   "m1-raw-primitive-trace-probe")),
        harness.parse_m1_raw_primitive_trace(output(replayed["raw-primitive-c-rust-trace"])))
    image = harness.parse_m1_compiler_tls_image_trace(c_trace(harness.M1_X86_64_COMPILER_TLS_TRACE_ARTIFACT_ROOT,
                                                            "m1-compiler-tls-image-trace-probe"))
    transition = harness.parse_m1_compiler_tls_transition_trace(c_trace(harness.M1_X86_64_COMPILER_TLS_TRACE_ARTIFACT_ROOT,
                                                                     "m1-compiler-tls-transition-trace-probe"))
    harness.compare_m1_compiler_tls_trace(harness.merge_m1_compiler_tls_trace(image, transition, source="retained C"),
        harness.parse_m1_compiler_tls_trace(output(replayed["compiler-tls-c-rust-trace"])))
    harness.compare_m1_compiler_tls_same_tld_trace(
        harness.parse_m1_compiler_tls_same_tld_trace(c_trace(harness.M1_X86_64_COMPILER_TLS_SAME_TLD_TRACE_ARTIFACT_ROOT,
                                                           "m1-compiler-tls-same-tld-trace-probe")),
        harness.parse_m1_compiler_tls_same_tld_trace(output(replayed["compiler-tls-same-tld-terminal-c-rust-trace"])))
    static = harness.parse_layout(c_trace(harness.M1_X86_64_STATIC_IMAGE_ARTIFACT_ROOT, "m1-static-image-probe"))
    release = harness.parse_layout(c_trace(harness.ARTIFACT_ROOT / "x86_64/oracle/release", "layout-probe"))
    layouts = harness.m1_foundations_layout_evidence(summary["components"], release,
        harness.parse_rust_layout(output(full)), static_image_c_layout=static)
    require(all(layouts[c["id"]] == c["layout_evidence"] for c in report["components"]), "layout observation changed")
    return report


def source_substrate_summary() -> dict[str, Any]:
    return harness.validate_x86_64_m2_memory_substrate_contract(
        harness.read_json(harness.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT), harness.load_pin())


def require_complete_substrate(summary: Mapping[str, Any]) -> None:
    open_components = [component["id"] for component in summary["components"]
                       if component["remaining_conditions"] or component["native_status"] != "complete"]
    require(summary["milestone"]["status"] == "complete" and not open_components,
            "memory substrate source contract remains incomplete: " + ", ".join(open_components))


def read_m1(path: Path | None = None) -> dict[str, Any]:
    report = harness.read_json(path or harness.M1_X86_64_FOUNDATIONS_REPORT)
    physical = report.get("physical_inputs", {})
    require(isinstance(physical, Mapping) and isinstance(physical.get("unit_program"), Mapping),
            "foundation receipt lacks the retained compiler-built unit program")
    summary = harness.validate_x86_64_m1_foundations_contract(
        harness.read_json(harness.M1_X86_64_FOUNDATIONS_CONTRACT), harness.load_pin())
    program = physical["unit_program"]
    require(program.get("execution") == summary["execution"]
            and program.get("cargo_target") == str(harness.M1_X86_64_FOUNDATIONS_CARGO_TARGET),
            "foundation unit build differs from the source execution contract")
    execution = summary["execution"]
    command = ["cargo", "test", "-p", execution["package"]]
    if execution.get("no_default_features") is True:
        command.append("--no-default-features")
    if execution.get("rust_target") is not None:
        command.extend(("--target", execution["rust_target"]))
    command.extend(("--locked", "--lib", "--no-run", "--message-format=json"))
    require(program.get("build_command") == command, "foundation compiler command differs from the source producer")
    authenticate_unit_program(program)
    require(all(harness.relative(Path(check["command"][0])) == program["artifact"]["path"]
                for component in report["components"] for check in component["executed_checks"]),
            "foundation checks used a different compiler product")
    return read_m1_components(path)


def authenticate_unit_program(program: Mapping[str, Any]) -> None:
    build = program.get("build")
    require(isinstance(build, Mapping) and build.get("status") == 0,
            "unit compiler build did not succeed")
    require(build.get("command") == program.get("build_command"), "unit compiler command changed")
    candidates = []
    for line in str(build.get("stdout", "")).splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == "crabc_mimalloc"
                and message.get("target", {}).get("kind") == ["lib"]
                and message.get("profile", {}).get("test") is True
                and message.get("executable")):
            candidates.append(message["executable"])
    artifact = program.get("artifact")
    require(isinstance(artifact, Mapping) and len(candidates) == 1
            and harness.relative(Path(candidates[0])) == artifact.get("path"),
            "compiler output does not identify the retained unit program")
    require(Path(candidates[0]).resolve().is_relative_to(Path(program["cargo_target"]).resolve()),
            "compiler unit program escapes its owned Cargo target")
    authenticate_artifacts(artifact, harness.ROOT)


def read_m2(path: Path | None = None) -> dict[str, Any]:
    summary = source_substrate_summary()
    require_complete_substrate(summary)
    report = harness.read_json(path or harness.M2_X86_64_MEMORY_SUBSTRATE_REPORT)
    authenticate_source(report, harness.m2_memory_substrate_source_state(), harness.m2_memory_substrate_source_attestation)
    require(report.get("milestone", {}).get("status") == "complete", "memory substrate receipt remains incomplete")
    inputs = report.get("producer_evidence")
    require(isinstance(inputs, Mapping), "memory substrate receipt lacks original producer inputs")
    # The renderer checks each source-defined producer contract rather than
    # treating its saved component completion labels as independent evidence.
    reconstructed = harness.m2_x86_64_memory_substrate_report(
        contract=harness.read_json(harness.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT),
        pin=harness.load_pin(), summary=summary, source_attestation=report["source"],
        focused_checks=[check for component in report["components"] for check in component["executed_checks"]],
        **inputs)
    require(all(report.get(key) == value for key, value in reconstructed.items()),
            "memory substrate receipt differs from its original producer")
    raise harness.HarnessError("memory substrate producer physical replay inputs are incomplete")


def read_m3(path: Path | None = None) -> dict[str, Any]:
    # Its prerequisite source contract is checked independently of a stored
    # prerequisites row, which cannot close an unfinished substrate condition.
    require_complete_substrate(source_substrate_summary())
    import m3_x86_64 as local
    contract = local.load_contract()
    report = harness.read_json(path or local.REPORT_PATH)
    authenticate_source(report, harness.runtime_ticket_zero_soak_source_state(),
                        harness.runtime_ticket_zero_soak_source_attestation)
    require(report.get("contract_sha256") == harness.file_digest(local.CONTRACT_PATH), "local engine contract changed")
    require(local.evaluate_gate(contract, report["checks"]) == report.get("gate"),
            "local engine receipt differs from its original producer")
    read_m1()
    read_m2()
    raise harness.HarnessError("local engine producer physical replay inputs are incomplete")


def read_report(milestone: str, path: Path | None = None) -> dict[str, Any]:
    readers = {"m1": read_m1, "m2": read_m2, "m3": read_m3}
    require(milestone in readers, f"unknown foundation receipt: {milestone}")
    return readers[milestone](path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("milestone", choices=("m1", "m2", "m3"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--components-only", action="store_true")
    arguments = parser.parse_args()
    try:
        require(not arguments.components_only or arguments.milestone == "m1", "component-only replay supports foundations only")
        (read_m1_components(arguments.report) if arguments.components_only
         else read_report(arguments.milestone, arguments.report))
    except (harness.HarnessError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"UNMET: {error}")
        return 1
    print("retained physical receipt replay passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
