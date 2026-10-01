"""Replay the original native foundation, substrate, and local-engine receipts.

Readers use the producing checkout's contract, clean source identity, native
image, artifact records and source trace parsers. A retained completion label
cannot override an open source condition or a missing physical observation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness

RECEIPT_ERROR = harness.HarnessError


def require(value: bool, detail: str) -> None:
    if not value:
        raise RECEIPT_ERROR(detail)


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


def execute(command: list[str] | tuple[str, ...], timeout: int, *,
            env: Mapping[str, str] | None = None, cwd: Path | None = None) -> dict[str, Any]:
    arguments = {"cwd": cwd or harness.ROOT, "timeout_seconds": timeout}
    if env is not None:
        arguments["env"] = env
    result = harness.command_record(command, **arguments)
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


def authenticate_unit_program(program: Mapping[str, Any], *, target: str = "crabc_mimalloc", kind: str = "lib",
                              expected_product: Mapping[str, Any] | None = None,
                              features: Sequence[str] | None = None) -> None:
    if expected_product is not None:
        require(program.get("build_command") == expected_product.get("build_command"),
                "local unit compiler command changed")
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
                and message.get("target", {}).get("name") == target
                and message.get("target", {}).get("kind") == [kind]
                and message.get("profile", {}).get("test") is True
                and message.get("executable")):
            if features is not None:
                require(isinstance(message.get("features"), list)
                        and sorted(message["features"]) == sorted(features),
                        "compiler-selected unit features differ from the source profile")
            candidates.append(message["executable"])
    artifact = program.get("artifact")
    require(isinstance(artifact, Mapping) and len(candidates) == 1
            and harness.relative(Path(candidates[0])) == artifact.get("path"),
            "compiler output does not identify the retained unit program")
    require(Path(candidates[0]).resolve().is_relative_to(Path(program["cargo_target"]).resolve()),
            "compiler unit program escapes its owned Cargo target")
    authenticate_artifacts(artifact, harness.ROOT)
    if expected_product is not None:
        # Cold and cached Cargo builds have different observations. Each build
        # must select the same authenticated physical executable.
        require(artifact == expected_product.get("artifact"),
                "local traces used another unit compiler product")


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


@contextmanager
def receipt_source(source_root: Path, *, native_only: bool = False):
    """Select a retained producer checkout without changing either source seal."""
    global harness
    receiver = harness
    receiver_root = Path(__file__).resolve().parents[2]
    seal_program = receiver_root / "compat/x86_64/native_shadow_receipt.py"
    committed_seal = subprocess.run(["git", "-c", "safe.directory=*", "-C", str(receiver_root),
                                     "show", "HEAD:compat/x86_64/native_shadow_receipt.py"], capture_output=True, check=False)
    require(committed_seal.returncode == 0 and committed_seal.stdout == seal_program.read_bytes(),
            "receiver source seal helper differs from committed source")
    seal_spec = importlib.util.spec_from_file_location("foundation_source_seal", seal_program)
    require(seal_spec is not None and seal_spec.loader is not None, "receiver source seal helper is unavailable")
    seals = importlib.util.module_from_spec(seal_spec)
    previous_seal = sys.modules.get(seal_spec.name)
    previous_bytecode = sys.dont_write_bytecode
    sys.modules[seal_spec.name] = seals
    try:
        sys.dont_write_bytecode = True
        exec(compile(committed_seal.stdout, str(seal_program), "exec"), seals.__dict__)
    finally:
        sys.dont_write_bytecode = previous_bytecode
        if previous_seal is None:
            sys.modules.pop(seal_spec.name, None)
        else:
            sys.modules[seal_spec.name] = previous_seal
    source_root = source_root.absolute()
    require(not source_root.is_symlink() and source_root == source_root.resolve(), "producer source alias escapes its physical root")
    receiver_identity = seals.source_seal(receiver_root)
    producer_identity = seals.source_seal(source_root)
    empty = hashlib.sha256(b"").hexdigest()
    require(receiver_identity["worktree_sha256"] == empty, "executing receiver source is not clean")
    require(producer_identity["worktree_sha256"] == empty, "retained producer source is not clean")
    saved_modules = {name: sys.modules.get(name) for name in ("run", "m3_x86_64", "x86_64_m3_queue_retirement", "native_shadow_receipt", "x86_64_foundation_gate_receipts")}
    saved_path = list(sys.path)
    previous_cache_prefix = sys.pycache_prefix
    cache_prefix = source_root / ".work" / ("reader-bytecode-" + uuid.uuid4().hex)
    require(not cache_prefix.exists(), "producer helper bytecode namespace is not empty")
    try:
        # Compiled Python caches are not source authority. An absent cache
        # prefix forces imports to read source without writing retained inputs.
        sys.dont_write_bytecode = True
        sys.pycache_prefix = str(cache_prefix)
        for name, relative in (("run", "compat/allocator/run.py"), ("m3_x86_64", "compat/allocator/m3_x86_64.py")):
            program = source_root / relative
            require(not program.is_symlink() and program.resolve().is_relative_to(source_root), "producer helper escapes retained source")
            committed = subprocess.run(["git", "-c", "safe.directory=*", "-C", str(source_root),
                                        "show", f"HEAD:{relative}"], capture_output=True, check=False)
            require(committed.returncode == 0 and committed.stdout == program.read_bytes(), "producer helper differs from its committed source")
            spec = importlib.util.spec_from_file_location(name, program)
            require(spec is not None and spec.loader is not None, "producer helper cannot be loaded")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        harness = sys.modules["run"]
        require(harness.ROOT == source_root and harness.WORK_ROOT.resolve().is_relative_to(source_root / ".work"),
                "producer mutable-state alias escapes retained source")
        sys.modules.pop("x86_64_m3_queue_retirement", None)
        sys.modules.pop("native_shadow_receipt", None)
        sys.path.insert(0, str(source_root / "compat/allocator"))
        yield receiver_identity, producer_identity
        require(not cache_prefix.exists(), "producer helper bytecode namespace changed during replay")
        destination = os.environ.get("CRABC_RECEIPT_REPLAY_OUTPUT")
        if destination:
            receiver.write_json(Path(destination) / "source-identities.json", {
                "executing_receiver": receiver_identity, "retained_producer": producer_identity,
                "scope": ("native-only diagnostic; Miri replay and foundation admission not performed"
                          if native_only else "local physical components; prerequisite admission unchanged"),
            })
        require(seals.source_seal(receiver_root) == receiver_identity, "executing receiver source changed during replay")
        require(seals.source_seal(source_root) == producer_identity, "retained producer source changed during replay")
    except Exception as error:
        receipts = sys.modules.get("native_shadow_receipt")
        receipt_error = getattr(receipts, "ReceiptError", RECEIPT_ERROR)
        if isinstance(error, (RuntimeError, receipt_error)):
            raise RECEIPT_ERROR(str(error)) from error
        raise
    finally:
        harness = receiver
        sys.path[:] = saved_path
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        sys.dont_write_bytecode = previous_bytecode
        sys.pycache_prefix = previous_cache_prefix


def read_m3_components(path: Path | None = None, *, source_root: Path | None = None,
                       native_only: bool = False) -> dict[str, Any]:
    if source_root is not None:
        with receipt_source(source_root, native_only=native_only):
            return read_m3_components(path, native_only=native_only)
    import m3_x86_64 as local
    contract = local.load_contract()
    report = harness.read_json(path or local.REPORT_PATH)
    authenticate_source(report, harness.runtime_ticket_zero_soak_source_state(),
                        harness.runtime_ticket_zero_soak_source_attestation)
    require(report.get("contract_sha256") == harness.file_digest(local.CONTRACT_PATH), "local engine contract changed")
    checks = report["checks"]
    require(local.evaluate_gate(contract, checks) == report.get("gate"),
            "local engine receipt differs from its original producer")
    require(all(component["status"] == "complete" and not component["unmet"]
                for component in report["gate"]["components"]), "local source components remain incomplete")
    required_checks = {name for component in contract["components"] for name in component["checks"]}
    require(set(checks) == required_checks | {"prerequisites"}
            and all(checks[name].get("status") == "passed" and checks[name].get("unmet") == []
                    for name in required_checks), "local selected check remains incomplete")
    interpreter_inputs = []
    for check_name, config_name in (("miri", "miri"), ("miri-ownership", "miri_ownership"),
                                    ("miri-guarded-ownership", "miri_guarded_ownership"),
                                    ("miri-page-ownership", "miri_page_ownership")):
        miri = checks[check_name]
        physical = miri.get("physical_inputs")
        require(isinstance(physical, Mapping) and isinstance(physical.get("program"), Mapping),
                "Miri receipt lacks compiler-selected physical inputs")
        selected = contract[config_name]
        base = local.miri_command(selected)
        flags = [*selected["miriflags"], f"-Zmiri-env-forward={local.FRESH_TEST_CHILD_ENV}"]
        listing = physical["listing"]
        require(listing["command"] == [*base, "--list", "--format", "terse"] and listing["status"] == 0,
                "Miri compiler listing differs from the source producer")
        require(miri["miriflags"] == flags and listing["environment"]["MIRIFLAGS"] == " ".join(flags)
                and local.FRESH_TEST_CHILD_ENV not in listing["environment"], "Miri strict listing environment changed")
        authority = local._miri_compiler_inputs(listing, selected)
        require(all(physical.get(key) == value for key, value in authority.items()),
                "Miri compiler-selected physical input authority changed")
        authenticate_artifacts(physical, harness.ROOT)
        probe = physical["probe"]
        require(probe["command"] == ["cargo", "miri", "--version"] and probe["status"] == 0
                and miri["version"] == probe["stdout"].strip()
                == authority["tools"]["cargo-miri"]["version"]["stdout"].strip(), "Miri selected interpreter version changed")
        metadata = harness.read_json(harness.ROOT / authority["program"]["path"])
        channel = tomllib.loads((harness.ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        tools = authority["tools"]
        expected_tool_directory = Path("/opt/rustup/toolchains") / f"{channel}-x86_64-unknown-linux-musl" / "bin"
        require(set(tools) == {"cargo-miri", "miri", "rustc", "cargo"}
                and all(Path(tool["executable_path"]) == expected_tool_directory / name
                        for name, tool in tools.items()), "Miri tools differ from the pinned source toolchain")
        groups = local.select_by_prefix(str(listing["stdout"]), selected["module_prefixes"])
        require(set(physical["commands"]) == set(groups) and set(miri["groups"]) == set(groups)
                and set(selected["required_tests"]) <= {name for names in groups.values() for name in names},
                "Miri selected test roster changed")
        expected_environment = listing["environment"]
        require(set(expected_environment) == {"MIRIFLAGS", "TMPDIR", "XDG_CACHE_HOME"},
                "Miri listing contains an undeclared environment override")
        require(expected_environment["TMPDIR"] == "/tmp"
                and expected_environment["XDG_CACHE_HOME"] == "/tmp/crabc-m3-miri-cache",
                "Miri temporary and cache aliases changed")
        for prefix, names in groups.items():
            rows = physical["commands"][prefix]
            require(names and len(rows) == len(names), "Miri exact-test command roster changed")
            for name, row in zip(names, rows, strict=True):
                require(row["command"] == [*base, "--exact", "--test-threads=1", name]
                        and row["status"] == 0
                        and row["environment"] == {**expected_environment, local.FRESH_TEST_CHILD_ENV: name},
                        "Miri exact command or fresh interpreter environment changed")
                require(local.TEST_RESULT.findall(output(row)) == [(name, "ok")]
                        and harness.parse_rust_test_count(output(row)) == 1,
                        "Miri original exact interpreter did not execute its selected test")
            aggregate = {"status": 0, "stdout": "\n".join(row["stdout"] for row in rows),
                         "stderr": "\n".join(row["stderr"] for row in rows)}
            require(local.summarize_group(prefix, names, aggregate) == miri["groups"][prefix],
                    "Miri selected group observations changed")
        require(miri["passed"] == sum(len(names) for names in groups.values()), "Miri original test total changed")
        logs = [f"### listing\n{json.dumps(listing['command'])}\n{listing['stdout']}\n{listing['stderr']}"]
        # JSON key sorting does not preserve the original group execution order.
        for prefix in groups:
            for row in physical["commands"][prefix]:
                name = row["command"][-1]
                logs.append(f"### {prefix} {name}\n{json.dumps(row['command'])}\n"
                            f"MIRIFLAGS={row['environment']['MIRIFLAGS']}\n"
                            f"{local.FRESH_TEST_CHILD_ENV}={name}\n{row['stdout']}\n{row['stderr']}")
        require((harness.ROOT / physical["log"]["path"]).read_text() == "\n".join(logs),
                "Miri raw compiler and interpreter log differs from its recorded commands")
        interpreter_inputs.append((check_name, metadata, expected_environment, authority, tools, listing, groups, selected))
    with harness.temporary_directory(prefix="local-receipt-reader-") as directory:
        scratch = Path(directory)
        pin = harness.load_pin()
        pinned = harness.safe_extract(harness.fetch_archive(pin, True), scratch / "oracle", pin["archive_root"])
        pinned_names = sorted(file.relative_to(pinned).as_posix()
                              for parent in (pinned / "include", pinned / "src")
                              for file in parent.rglob("*") if file.is_file())
        for check in checks.values():
            authenticate_artifacts(check.get("physical_inputs", {}), pinned)
        unit_programs = {}
        for check_name, config_name in (("rust-unit-batch", "rust_unit_batch"),
                                        ("rust-page-ownership-batch", "rust_page_ownership_batch")):
            expected_unit_build = local.unit_test_command(contract[config_name] if check_name == "rust-page-ownership-batch" else None)
            unit = checks[check_name]
            unit_inputs = unit["physical_inputs"]
            unit_program = {**unit_inputs["build"], "cargo_target": str(harness.WORK_ROOT / "target")}
            require(unit_program["build_command"] == expected_unit_build, "local unit compiler command changed")
            authenticate_unit_program(unit_program, features=local.cargo_selected_features(
                contract[config_name] if check_name == "rust-page-ownership-batch" else {}))
            binary = str(harness.ROOT / unit_program["artifact"]["path"])
            require(unit_inputs["binary"] == unit_program["artifact"] and unit["binary"] == binary,
                    "local unit observations name another compiler product")
            unit_listing = unit_inputs["listing"]
            require(unit_listing["command"] == [binary, "--list", "--format", "terse"]
                    and unit_listing["status"] == 0, "local unit listing command changed")
            observed_listing = execute(unit_listing["command"], 600)
            require(local.TEST_LISTING.findall(observed_listing["stdout"]) == local.TEST_LISTING.findall(unit_listing["stdout"]),
                    "local retained unit compiler product selects different tests")
            unit_groups = local.select_by_prefix(unit_listing["stdout"], contract[config_name]["module_prefixes"])
            require(set(unit_inputs["commands"]) == set(unit_groups) and set(unit["groups"]) == set(unit_groups),
                    "local unit group roster changed")
            for prefix, names in unit_groups.items():
                row = unit_inputs["commands"][prefix]
                require(names and row["command"] == [binary, "--exact", "--test-threads=1", *names]
                        and row["status"] == 0, "local unit exact group command changed")
                expected_results = [(name, "ok") for name in names]
                require(sorted(local.TEST_RESULT.findall(output(row))) == sorted(expected_results)
                        and local.summarize_group(prefix, names, row) == unit["groups"][prefix],
                        "local original unit observations changed")
                replay = execute(row["command"], 7200)
                require(sorted(local.TEST_RESULT.findall(output(replay))) == sorted(expected_results),
                        "local retained unit observation changed")
            require(unit["passed"] == sum(len(names) for names in unit_groups.values()), "local unit test total changed")
            unit_programs[check_name] = unit_program
        unit_program = unit_programs["rust-unit-batch"]
        binary = str(harness.ROOT / unit_program["artifact"]["path"])
        for check_name, owner_profile in (("local-trace-differential", None),
                                          ("persistent-owner-trace-differential", contract["persistent_owner_profile"])):
            check = checks[check_name]
            inputs = check["physical_inputs"]
            c_binary = harness.ROOT / inputs["artifact"]["path"]
            source = c_binary.parent / "source" / pin["archive_root"]
            require(source.resolve().is_relative_to(local.ARTIFACT_ROOT.resolve())
                    and harness.source_file_records(source, pinned_names) == harness.source_file_records(pinned, pinned_names),
                    "local C compiler inputs differ from the pinned source")
            build = inputs["build"]
            require(build["status"] == 0 and build["command"] == local.c_driver_command(
                harness.require_tool("musl-gcc"), source, c_binary, contract), "local C compiler command changed")
            expected_sources = [*contract["c_oracle"]["release_source_set"],
                                "include/mimalloc.h", "include/mimalloc/internal.h", "include/mimalloc/types.h"]
            require(inputs["source_files"] == harness.source_file_records(pinned, expected_sources)
                    and check["archive_sha256"] == pin["sha256"]
                    and check["c_driver_sha256"] == harness.sha256_file(local.C_DRIVER_PATH),
                    "local C source authority changed")
            require(check["rust_driver_sha256"] == harness.sha256_file(
                local.OWNER_RUST_DRIVER_PATH if owner_profile else local.RUST_DRIVER_PATH), "local Rust driver changed")
            if owner_profile:
                require(check["trace_audit_sha256"] == harness.sha256_file(local.OWNER_TRACE_AUDIT_PATH),
                        "persistent owner trace audit changed")
            private_c = scratch / (check_name + "-c")
            recompile = list(build["command"])
            recompile[recompile.index("-o") + 1] = str(private_c)
            execute(recompile, 600, cwd=source)
            require(harness.sha256_file(private_c) == inputs["artifact"]["sha256"],
                    "retained C program differs from its original compiler inputs")
            rust = inputs["rust_program"]
            if owner_profile:
                driver = owner_profile["rust_driver"]
                expected_build = ["cargo", "test", "--locked", "--target", local.TARGET, "-p", "crabc-mimalloc",
                                  "--no-default-features", "--features", ",".join(driver["features"]),
                                  "--test", driver["target"], "--no-run", "--message-format=json"]
                require(rust["build_command"] == expected_build, "owner compiler command changed")
                authenticate_unit_program({**rust, "cargo_target": str(harness.WORK_ROOT / "target")},
                                          target=driver["target"], kind="test")
                rust_test = driver["test"]
            else:
                authenticate_unit_program({**rust, "cargo_target": str(harness.WORK_ROOT / "target")},
                                          expected_product=unit_program, features=local.cargo_selected_features({}))
                rust_test = local.RUST_TRACE_TEST
            rust_binary = str(harness.ROOT / rust["artifact"]["path"])
            workloads = (local.generate_owner_workloads(contract) if owner_profile else local.generate_workloads(contract))
            roster = [(name, owner) for name in workloads
                      for owner in (owner_profile["owners"] if owner_profile else ["local"])]
            require([(row["id"], row.get("owner", "local")) for row in check["workloads"]] == roster,
                    "local differential workload or owner roster changed")
            reconstructed_coverage = []
            for index, (row, (name, owner)) in enumerate(zip(check["workloads"], roster, strict=True)):
                retained = row["physical_inputs"]
                workload = harness.ROOT / retained["workload"]["path"]
                require(workload.read_text() == workloads[name]
                        and row["workload_sha256"] == local.sha256_bytes(workloads[name].encode()),
                        "local differential workload changed")
                c_lines = (harness.ROOT / retained["c_trace"]["path"]).read_text().splitlines()
                require(c_lines == (harness.ROOT / retained["c_repeat"]["path"]).read_text().splitlines()
                        == (harness.ROOT / retained["rust_trace"]["path"]).read_text().splitlines()
                        and row["c_repeat_identical"] is True and row["divergence"] is None
                        and row["status"] == "matched" and row["trace_lines"] == len(c_lines)
                        and row["c_trace_sha256"] == retained["c_trace"]["sha256"]
                        and row["rust_trace_sha256"] == retained["rust_trace"]["sha256"],
                        "local retained differential observations disagree")
                coverage = local.trace_coverage(c_lines)
                require(coverage == row["coverage"], "local retained trace coverage changed")
                reconstructed_coverage.append(coverage)
                if not owner_profile:
                    specification = next(entry for entry in contract["workloads"] if entry["id"] == name)
                    witness = None
                    if specification["generator"] == "queue-candidate-front":
                        parameters = specification["parameters"]
                        witness = local.queue_candidate_front_witness(c_lines, int(parameters["size"]),
                                                                      int(parameters["freed_from_first"]))
                    # Source snapshots use tuples; their retained JSON uses arrays.
                    # Compare JSON values while preserving field names and scalar types.
                    require(json.dumps(row["queue_candidate_front"], sort_keys=True, allow_nan=False)
                            == json.dumps(witness, sort_keys=True, allow_nan=False)
                            and (witness is None or not witness["unmet"]),
                                "local queue candidate witness changed")
                for repeat in range(2):
                    trace = scratch / f"{check_name}-{index}-c-{repeat}.trace"
                    execute([str(c_binary), str(workload), str(trace), owner], 1800,
                            env=local.c_environment(owner_profile["c_environment"] if owner_profile else contract["c_oracle"]["environment"]),
                            cwd=workload.parent)
                    require(trace.read_text().splitlines() == c_lines, "retained C local differential changed")
                trace = scratch / f"{check_name}-{index}-rust.trace"
                environment = {key: value for key, value in os.environ.items() if not key.lower().startswith("mimalloc_")}
                if owner_profile:
                    environment.update({local.OWNER_ENV: owner, local.OWNER_WORKLOAD_ENV: str(workload),
                                        local.OWNER_OUTPUT_ENV: str(trace)})
                else:
                    environment.update({local.WORKLOAD_ENV: str(workload), local.OUTPUT_ENV: str(trace)})
                replay = execute([rust_binary, rust_test, "--exact", "--nocapture", "--test-threads=1"],
                                 3600, env=environment)
                require(harness.parse_rust_test_count(output(replay)) == 1 and trace.read_text().splitlines() == c_lines,
                        "retained Rust local differential changed")
            if owner_profile:
                coverage = {owner: local.merge_coverage(row["coverage"] for row in check["workloads"] if row["owner"] == owner)
                            for owner in owner_profile["owners"]}
                require(check["coverage"] == coverage and all(not local.owner_coverage_unmet(value, owner_profile["coverage_requirements"])
                                                              for value in coverage.values()), "owner coverage remains incomplete")
            else:
                coverage = local.merge_coverage(reconstructed_coverage)
                require(check["coverage"] == coverage and check["coverage_unmet"] == []
                        and not local.coverage_unmet(coverage, contract["coverage_requirements"]), "local coverage remains incomplete")
        reorder = checks["queue-reorder-differential"]
        runtime = harness.read_json(harness.ROOT / reorder["physical_inputs"]["receipt"]["path"])
        require(reorder["raw_runtime_receipt"] == str(harness.ROOT / reorder["physical_inputs"]["receipt"]["path"])
                and runtime["physical_inputs"] == {key: reorder["physical_inputs"][key] for key in ("c_program", "rust_program")}
                and runtime["physical_inputs"]["rust_program"] == unit_program["artifact"],
                "queue reorder receipt names another compiler product")
        fixture = contract["queue_reorder_differential"]
        require(runtime["c_fixture_sha256"] == reorder["c_fixture_sha256"] == harness.sha256_file(harness.ROOT / fixture["c_fixture"])
                and runtime["runner_sha256"] == reorder["runner_sha256"] == harness.sha256_file(harness.ROOT / fixture["runner"])
                and runtime["rust_source_sha256"] == reorder["rust_source_sha256"] == harness.sha256_file(harness.ROOT / "crabc-mimalloc/src/page_queue.rs")
                and runtime["archive_sha256"] == reorder["archive_sha256"] == pin["sha256"]
                and runtime["rust_test"] == reorder["rust_test"] == fixture["rust_test"], "queue reorder source authority changed")
        reorder_c = harness.ROOT / runtime["physical_inputs"]["c_program"]["path"]
        reorder_source = reorder_c.parent / "source" / pin["archive_root"]
        require(harness.source_file_records(reorder_source, pinned_names) == harness.source_file_records(pinned, pinned_names),
                "queue reorder compiler inputs differ from the pin")
        expected_c = [harness.require_tool("musl-gcc"), "-std=c11", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                      "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
                      "-I", str(reorder_source / "include"), "-I", str(reorder_source / "src"),
                      str(harness.ROOT / fixture["c_fixture"]), "-o", str(reorder_c)]
        require(runtime["c_build"]["command"] == expected_c and runtime["c_build"]["status"] == 0,
                "queue reorder C compiler command changed")
        private_c = scratch / "reorder-c"
        expected_c[-1] = str(private_c)
        execute(expected_c, 600)
        require(harness.sha256_file(private_c) == runtime["physical_inputs"]["c_program"]["sha256"], "queue reorder C compiler product changed")
        rust_command = [binary, fixture["rust_test"], "--exact", "--nocapture", "--test-threads=1"]
        require(runtime["c_runtime"]["command"] == [str(reorder_c)] and runtime["c_runtime"]["status"] == 0
                and runtime["rust_runtime"]["command"] == rust_command and runtime["rust_runtime"]["status"] == 0,
                "queue reorder runtime commands changed")
        c_lines = runtime["c_runtime"]["stdout"].splitlines()
        rust_lines = re.findall(r"M3Q [^\r\n]+", runtime["rust_runtime"]["stdout"])
        expected = (("start", "ABC", ""), ("first-full", "BC", "A"), ("middle-full", "C", "AB"),
                    ("full-front", "C", "BA"), ("second-position", "CB", "A"), ("full-return", "CBA", ""))
        require(c_lines == rust_lines and len(c_lines) == len(expected)
                and harness.parse_rust_test_count(output(runtime["rust_runtime"])) == 1, "queue reorder observations disagree")
        for line, (step, regular, full) in zip(c_lines, expected, strict=True):
            total = sum({"A": 128, "B": 192, "C": 256}[page] for page in full)
            require(line == f"M3Q {step} regular={regular} full={full} bytes={total} pages=3", "queue reorder transition changed")
        require(re.findall(r"M3Q [^\r\n]+", execute(rust_command, 600)["stdout"]) == c_lines
                and execute([str(reorder_c)], 600)["stdout"].splitlines() == c_lines,
                "retained queue reorder observation changed")
        retirement = checks["queue-retirement-differential"]
        import x86_64_m3_queue_retirement as queue
        queue_report = queue.read_report(replay=True)
        require(retirement["raw_driver_receipt"] == str(local.ARTIFACT_ROOT / "queue-retirement-driver.json")
                and queue_report == harness.read_json(Path(retirement["raw_driver_receipt"])),
                "queue retirement aggregate names another original producer")
        fixture = contract["queue_retirement_differential"]
        for key, source_path in (("c_fixture_sha256", fixture["c_fixture"]), ("runner_sha256", fixture["runner"]),
                                 ("rust_source_sha256", "crabc-mimalloc/src/page_queue.rs"),
                                 ("rust_free_list_sha256", "crabc-mimalloc/src/free_list.rs")):
            require(retirement[key] == harness.sha256_file(harness.ROOT / source_path), "queue retirement source authority changed")
        require([retirement[key] for key in ("rust_test", "rust_matrix_test", "rust_free_test")]
                == [fixture[key] for key in ("rust_test", "rust_matrix_test", "rust_free_test")], "queue retirement selected tests changed")
        for key, filename in (("c_trace_sha256", "queue-retirement.c.trace"), ("rust_trace_sha256", "queue-retirement.rust.trace"),
                              ("trace_sha256", "queue-retirement.trace")):
            require(retirement[key] == harness.sha256_file(local.ARTIFACT_ROOT / filename), "queue retirement original trace changed")
        require((local.ARTIFACT_ROOT / "queue-retirement.c.trace").read_text().splitlines()
                == (local.ARTIFACT_ROOT / "queue-retirement.rust.trace").read_text().splitlines(),
                "queue retirement aggregate observations disagree")
        for check_name, metadata, expected_environment, authority, tools, listing, groups, selected in interpreter_inputs:
            if not native_only:
                # The interpreter recompiles its test input. Retained inputs stay
                # read-only; compiler outputs and incremental state use fresh scratch.
                private = json.loads(json.dumps(metadata))
                arguments = private["args"]
                require(arguments.count("--out-dir") == 1, "Miri compiler output directory is ambiguous")
                out_index = arguments.index("--out-dir") + 1
                incremental = [index + 1 for index, value in enumerate(arguments[:-1])
                               if value == "-C" and arguments[index + 1].startswith("incremental=")]
                require(len(incremental) == 1, "Miri compiler incremental directory is ambiguous")
                interpreter_scratch = scratch / check_name
                interpreter_scratch.mkdir()
                compiler_output = interpreter_scratch / "compiler-output"
                compiler_output.mkdir()
                transformations = [
                    {"original": arguments[out_index], "private": str(compiler_output)},
                    {"original": arguments[incremental[0]], "private": "incremental=" + str(interpreter_scratch / "incremental")},
                ]
                arguments[out_index] = transformations[0]["private"]
                arguments[incremental[0]] = transformations[1]["private"]
                private_program = interpreter_scratch / "compiler-runner.json"
                harness.write_json(private_program, private)
                environment = dict(os.environ, **expected_environment, **authority["phase_environment"])
                environment.pop(local.FRESH_TEST_CHILD_ENV, None)
                runner = [tools["cargo-miri"]["executable_path"], "runner", str(private_program)]
                replay_listing = execute([*runner, "--list", "--format", "terse"], 7200, env=environment)
                require(local.TEST_LISTING.findall(replay_listing["stdout"]) == local.TEST_LISTING.findall(listing["stdout"]),
                        "Miri retained compiler input selects different tests")
                for prefix, names in groups.items():
                    for name in names:
                        replay = execute([*runner, "--exact", "--test-threads=1", name], 7200,
                                         env={**environment, local.FRESH_TEST_CHILD_ENV: name})
                        require(local.TEST_RESULT.findall(output(replay)) == [(name, "ok")]
                                and harness.parse_rust_test_count(output(replay)) == 1,
                                "Miri retained interpreter observation changed")
                destination = os.environ.get("CRABC_RECEIPT_REPLAY_OUTPUT")
                if destination:
                    harness.write_json(Path(destination) / (check_name + "-private-output-transform.json"), {
                        "program": authority["program"], "transformations": transformations,
                        "private_program": private, "phase_environment": authority["phase_environment"],
                    })
            require(local._miri_compiler_inputs(listing, selected) == authority,
                    "Miri retained input authority changed during replay")
        for check in checks.values():
            authenticate_artifacts(check.get("physical_inputs", {}), pinned)
    authenticate_source(report, harness.runtime_ticket_zero_soak_source_state(),
                        harness.runtime_ticket_zero_soak_source_attestation)
    return ({"scope": "native-only-diagnostic", "miri_replayed": False}
            if native_only else report)


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
    return read_m3_components(path)


def read_report(milestone: str, path: Path | None = None) -> dict[str, Any]:
    readers = {"m1": read_m1, "m2": read_m2, "m3": read_m3}
    require(milestone in readers, f"unknown foundation receipt: {milestone}")
    return readers[milestone](path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("milestone", choices=("m1", "m2", "m3"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--components-only", action="store_true")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--native-only", action="store_true")
    arguments = parser.parse_args()
    try:
        require(not arguments.components_only or arguments.milestone in ("m1", "m3"),
                "component-only replay supports foundations and local engine only")
        require(arguments.source_root is None or (arguments.components_only and arguments.milestone == "m3"),
                "retained source selection supports local component replay only")
        require(not arguments.native_only or (arguments.components_only and arguments.milestone == "m3"),
                "native-only replay requires local component diagnostic mode")
        if arguments.components_only:
            if arguments.milestone == "m3":
                if arguments.native_only:
                    read_m3_components(arguments.report, source_root=arguments.source_root, native_only=True)
                elif arguments.source_root is None:
                    read_m3_components(arguments.report)
                else:
                    read_m3_components(arguments.report, source_root=arguments.source_root)
            else:
                read_m1_components(arguments.report)
        else:
            read_report(arguments.milestone, arguments.report)
    except (harness.HarnessError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"UNMET: {error}")
        return 1
    print("retained native boundaries replay passed; Miri replay not performed"
          if arguments.native_only else "retained physical receipt replay passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
