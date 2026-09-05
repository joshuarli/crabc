#!/usr/bin/env python3
"""Seal native owned-product evidence for the frozen signal/process workload.

This is a bounded component, not a qualification coordinator.  It compiles the
one unchanged frozen workload through a supplied installed dynamic driver,
records that source/header/object boundary, and preserves exact process-group
observations for the same object linked against the pinned musl oracle and
supplied owned products.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from typing import Any, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from owned_posix_product_evidence import (
    ProductEvidenceError,
    _validate_dynamic_product,
    _validate_static_product,
    validate_link,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "compat" / "signal-process" / "tests" / "signal_process.c"
SIGNAL_PROCESS_SUBCASES = (
    "siginfo",
    "nodefer",
    "mask-pending",
    "sa-restart",
    "altstack",
    "thread-mask",
    "sigwait",
    "timer",
    "wait-signal",
    "wait-nohang",
    "atfork",
    "fork-worker-exec",
)
COMPILE_INPUT_SCHEMA = "crabc.x86_64-owned-signal-process-compile-inputs/v1"
COMPILE_SCHEMA = "crabc.x86_64-owned-signal-process-compile/v1"
EXECUTION_PAYLOAD_SCHEMA = "crabc.x86_64-owned-signal-process-execution-payload/v1"
ORACLE_SCHEMA = "crabc.x86_64-owned-signal-process-oracle/v1"
OBSERVATION_SCHEMA = "crabc.x86_64-owned-signal-process-observations/v1"
MAX_TIMEOUT = 300.0


class SignalProcessEvidenceError(RuntimeError):
    """A source, product, link, or retained observation is not trustworthy."""


def fail(message: str) -> None:
    raise SignalProcessEvidenceError(message)


def physical(path: Path, description: str, *, directory: bool = False) -> Path:
    """Reject lexical traversal and every symlink hop before consuming a path."""

    if ".." in path.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        mode = absolute.lstat().st_mode
    except OSError as error:
        raise SignalProcessEvidenceError(f"{description} is unreadable: {path}") from error
    if directory:
        if not stat.S_ISDIR(mode):
            fail(f"{description} is not a physical directory: {path}")
    elif not stat.S_ISREG(mode):
        fail(f"{description} is not a physical regular file: {path}")
    return absolute


def sha256(path: Path) -> str:
    path = physical(path, "hashed artifact")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise SignalProcessEvidenceError(f"cannot hash artifact: {path}") from error
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, str]:
    path = physical(path, "recorded artifact")
    return {"path": str(path), "sha256": sha256(path)}


def exact_record(value: object, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{description} fields drifted")
    return value


def read_json(path: Path, description: str) -> dict[str, Any]:
    path = physical(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignalProcessEvidenceError(f"{description} is not JSON: {path}") from error
    if not isinstance(value, dict):
        fail(f"{description} is not an object")
    return value


def assert_recorded_file(value: object, path: Path, description: str) -> None:
    record = exact_record(value, {"path", "sha256"}, description)
    path = physical(path, description)
    if record["path"] != str(path) or record["sha256"] != sha256(path):
        fail(f"{description} identity drifted")


def require_within(path: Path, root: Path, description: str) -> Path:
    path = physical(path, description)
    root = physical(root, "evidence root", directory=True)
    if not path.is_relative_to(root):
        fail(f"{description} escapes the evidence root: {path}")
    return path


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    """Publish one canonical record only once; a replacement is evidence drift."""

    parent = physical(path.parent, "evidence record parent", directory=True)
    if path.parent != parent or path.exists() or path.is_symlink():
        fail(f"evidence record already exists or is unsafe: {path}")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise SignalProcessEvidenceError(f"cannot write evidence record: {path}") from error


def supplied_product(root: Path, product: Path, kind: str) -> Path:
    root = physical(root, "checkout root", directory=True)
    product = physical(product, f"signal-process {kind} product", directory=True)
    if not product.is_relative_to(root / ".work"):
        fail(f"signal-process {kind} product must be a physical checkout .work directory")
    try:
        if kind == "dynamic":
            _validate_dynamic_product(product)
        elif kind == "static":
            _validate_static_product(product)
        else:
            fail("unknown supplied product kind")
    except ProductEvidenceError as error:
        raise SignalProcessEvidenceError(f"signal-process {kind} product validation failed: {error}") from error
    return product


def dynamic_product(product: Path) -> tuple[Path, Path, Path]:
    root = supplied_product(ROOT, product, "dynamic")
    try:
        manifest, _ = _validate_dynamic_product(root)
    except ProductEvidenceError as error:
        raise SignalProcessEvidenceError(f"signal-process dynamic product validation failed: {error}") from error
    driver = physical(root / "bin" / "crabc-cc-dynamic", "installed dynamic driver")
    if not driver.stat().st_mode & 0o111:
        fail("installed dynamic driver is not executable")
    return root, physical(manifest, "dynamic manifest"), driver


def installed_policy(product: Path) -> tuple[Any, Path, Path]:
    helper = physical(
        product / "share" / "crabc" / "crabc_cc_static.py", "installed compiler helper"
    )
    spec = importlib.util.spec_from_file_location("owned_signal_process_compiler", helper)
    if spec is None or spec.loader is None:
        fail("installed compiler helper is unreadable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        compiler = physical(Path(module.compiler()).resolve(strict=True), "installed compiler")
    except (OSError, AttributeError, RuntimeError) as error:
        raise SignalProcessEvidenceError("installed compiler helper could not select a compiler") from error
    return module, helper, compiler


def driver_compile_command(driver: Path, source: Path, object_path: Path) -> list[str]:
    return [
        str(driver), "--dynamic-pie", "-std=c11", "-fno-builtin", "-c", str(source),
        "-o", str(object_path),
    ]


def dependency_command(compiler: Path, product: Path, source: Path) -> list[str]:
    return [
        str(compiler), "-nostdinc", "-isystem", str(product / "usr" / "include"),
        "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-std=c11", "-fPIE",
        "-M", "-H", str(source),
    ]


def dependency_headers(dependency_file: Path, product: Path, source: Path) -> list[dict[str, str]]:
    try:
        text = physical(dependency_file, "installed header dependency file").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise SignalProcessEvidenceError("installed header dependency file is unreadable") from error
    if ":" not in text:
        fail("installed header dependency file lacks a target")
    dependencies: set[Path] = set()
    for word in text.replace("\\\n", " ").split(":", 1)[1].split():
        path = physical(Path(word), "installed header dependency")
        if path == source:
            dependencies.add(path)
            continue
        if not path.is_relative_to(product / "usr" / "include"):
            fail(f"installed header dependency escapes the product headers: {path}")
        dependencies.add(path)
    if source not in dependencies:
        fail("installed header dependency file omits the workload source")
    headers = sorted(dependencies - {source})
    if not headers:
        fail("installed header dependency file omits installed headers")
    return [file_record(path) for path in headers]


def planned_object_path(path: Path, description: str) -> Path:
    """Return a safe intended object path before or after its sole compile."""

    absolute = Path(os.path.abspath(path))
    physical(absolute.parent, f"{description} parent", directory=True)
    if absolute.exists() or absolute.is_symlink():
        return physical(absolute, description)
    return absolute


def snapshot_compile_inputs(product: Path, source: Path, object_path: Path, snapshot: Path) -> dict[str, Any]:
    """Capture every translation input before the dynamic driver makes an object."""

    product, manifest, driver = dynamic_product(product)
    source = physical(source, "signal-process source")
    if source != physical(SOURCE, "frozen signal-process source"):
        fail("signal-process source differs from the frozen workload")
    object_path = planned_object_path(object_path, "planned signal-process workload object")
    snapshot = Path(os.path.abspath(snapshot))
    physical(snapshot.parent, "compile input snapshot parent", directory=True)
    if snapshot.exists() or snapshot.is_symlink():
        fail("compile input snapshot already exists or is unsafe")
    policy, helper, compiler = installed_policy(product)
    environment = policy.clean_environment()
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
    ):
        fail("installed compiler clean environment is malformed")
    before = {
        "product_manifest": file_record(manifest),
        "source": file_record(source),
        "driver": file_record(driver),
        "compiler_helper": file_record(helper),
        "compiler": file_record(compiler),
    }
    dependencies = snapshot.with_suffix(".dependencies")
    header_trace = snapshot.with_suffix(".headers")
    status = snapshot.with_suffix(".header-status")
    for artifact in (dependencies, header_trace, status):
        if artifact.exists() or artifact.is_symlink():
            fail(f"compile input snapshot path already exists or is unsafe: {artifact}")
    command = dependency_command(compiler, product, source)
    try:
        with dependencies.open("xb") as stdout, header_trace.open("xb") as stderr:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env=environment, check=False,
            )
        with status.open("x", encoding="ascii", newline="\n") as output:
            output.write(f"{result.returncode}\n")
    except OSError as error:
        raise SignalProcessEvidenceError("installed-header input snapshot could not run") from error
    if result.returncode != 0:
        fail("installed-header input snapshot failed")
    for name, identity in before.items():
        assert_recorded_file(identity, Path(identity["path"]), f"precompile {name}")
    record = {
        "schema": COMPILE_INPUT_SCHEMA,
        **before,
        "planned_object": str(object_path),
        "driver_compile_command": driver_compile_command(driver, source, object_path),
        "dependency_audit_command": command,
        "clean_environment": dict(sorted(environment.items())),
        "dependency_file": file_record(dependencies),
        "header_trace": file_record(header_trace),
        "header_status": file_record(status),
        "headers": dependency_headers(dependencies, product, source),
    }
    write_new_json(snapshot, record)
    return record


def validate_compile_inputs(product: Path, source: Path, object_path: Path, snapshot: Path) -> dict[str, Any]:
    """Recheck the precompile snapshot without making another workload object."""

    product, manifest, driver = dynamic_product(product)
    source = physical(source, "signal-process source")
    if source != physical(SOURCE, "frozen signal-process source"):
        fail("signal-process source differs from the frozen workload")
    object_path = planned_object_path(object_path, "planned signal-process workload object")
    snapshot = physical(snapshot, "signal-process compile input snapshot")
    record = read_json(snapshot, "signal-process compile input snapshot")
    expected = {
        "schema", "product_manifest", "source", "planned_object", "driver", "compiler_helper",
        "compiler", "driver_compile_command", "dependency_audit_command", "clean_environment",
        "dependency_file", "header_trace", "header_status", "headers",
    }
    if set(record) != expected or record["schema"] != COMPILE_INPUT_SCHEMA:
        fail("signal-process compile input snapshot schema drifted")
    for name, current in (
        ("product_manifest", manifest), ("source", source), ("driver", driver),
    ):
        assert_recorded_file(record[name], current, f"snapshot {name}")
    policy, helper, compiler = installed_policy(product)
    assert_recorded_file(record["compiler_helper"], helper, "snapshot compiler helper identity")
    assert_recorded_file(record["compiler"], compiler, "snapshot compiler identity")
    if record["planned_object"] != str(object_path):
        fail("snapshot planned object path drifted")
    if record["driver_compile_command"] != driver_compile_command(driver, source, object_path):
        fail("snapshot installed driver compile command drifted")
    command = dependency_command(compiler, product, source)
    if record["dependency_audit_command"] != command:
        fail("snapshot installed header audit command drifted")
    environment = policy.clean_environment()
    if record["clean_environment"] != dict(sorted(environment.items())):
        fail("snapshot compiler clean environment drifted")
    for name, suffix in (
        ("dependency_file", ".dependencies"),
        ("header_trace", ".headers"),
        ("header_status", ".header-status"),
    ):
        assert_recorded_file(record[name], snapshot.with_suffix(suffix), f"snapshot {name} identity")
    if snapshot.with_suffix(".header-status").read_bytes() != b"0\n":
        fail("snapshot installed header audit status drifted")
    if not isinstance(record["headers"], list) or not record["headers"]:
        fail("snapshot headers drifted")
    if record["headers"] != dependency_headers(snapshot.with_suffix(".dependencies"), product, source):
        fail("snapshot header identities drifted")
    return record


def record_compile(
    product: Path, source: Path, object_path: Path, snapshot: Path, audit: Path
) -> dict[str, Any]:
    """Bind the postcompile object to the earlier complete input snapshot."""

    inputs = validate_compile_inputs(product, source, object_path, snapshot)
    object_path = physical(object_path, "signal-process workload object")
    audit = Path(os.path.abspath(audit))
    physical(audit.parent, "compile audit parent", directory=True)
    if audit.exists() or audit.is_symlink():
        fail("signal-process compile audit already exists or is unsafe")
    record = {
        "schema": COMPILE_SCHEMA,
        "input_snapshot": file_record(snapshot),
        "object": file_record(object_path),
        "driver_compile_command": inputs["driver_compile_command"],
    }
    write_new_json(audit, record)
    return record


def validate_compile(product: Path, source: Path, object_path: Path, audit: Path) -> dict[str, Any]:
    """Recheck precompile inputs and their one resulting object during sealing."""

    object_path = physical(object_path, "signal-process workload object")
    audit = physical(audit, "signal-process compile audit")
    record = read_json(audit, "signal-process compile audit")
    expected = {"schema", "input_snapshot", "object", "driver_compile_command"}
    if set(record) != expected or record["schema"] != COMPILE_SCHEMA:
        fail("signal-process compile audit schema drifted")
    snapshot = Path(exact_record(record["input_snapshot"], {"path", "sha256"}, "compile input snapshot")["path"])
    inputs = validate_compile_inputs(product, source, object_path, snapshot)
    assert_recorded_file(record["input_snapshot"], snapshot, "compile input snapshot")
    assert_recorded_file(record["object"], object_path, "compile object")
    if record["driver_compile_command"] != inputs["driver_compile_command"]:
        fail("compile driver command drifted")
    product_manifest = Path(exact_record(inputs["product_manifest"], {"path", "sha256"}, "snapshot manifest")["path"])
    driver = Path(exact_record(inputs["driver"], {"path", "sha256"}, "snapshot driver")["path"])
    helper = Path(exact_record(inputs["compiler_helper"], {"path", "sha256"}, "snapshot helper")["path"])
    compiler = Path(exact_record(inputs["compiler"], {"path", "sha256"}, "snapshot compiler")["path"])
    return {
        "schema": COMPILE_SCHEMA,
        "compile_audit": file_record(audit),
        "input_snapshot": file_record(snapshot),
        "source": file_record(source),
        "object": file_record(object_path),
        "product_manifest": file_record(product_manifest),
        "driver": file_record(driver),
        "compiler_helper": file_record(helper),
        "compiler": file_record(compiler),
        "headers": inputs["headers"],
    }

def record_oracle(oracle_cc: Path, object_path: Path, binary: Path, record_path: Path) -> dict[str, Any]:
    oracle_cc = physical(oracle_cc, "pinned musl compiler")
    object_path = physical(object_path, "signal-process workload object")
    binary = physical(binary, "pinned musl signal-process binary")
    musl_archive = physical(Path("/opt/musl-1.2.6/lib/libc.a"), "pinned musl libc archive")
    record = {
        "schema": ORACLE_SCHEMA,
        "compiler": file_record(oracle_cc),
        "musl_libc_archive": file_record(musl_archive),
        "object": file_record(object_path),
        "binary": file_record(binary),
        "link_command": [
            str(oracle_cc), "-static", "-fno-pie", "-no-pie", "-pthread", str(object_path),
            "-o", str(binary),
        ],
    }
    write_new_json(record_path, record)
    return record


def validate_oracle(oracle_cc: Path, object_path: Path, binary: Path, record_path: Path) -> dict[str, Any]:
    oracle_cc = physical(oracle_cc, "pinned musl compiler")
    object_path = physical(object_path, "signal-process workload object")
    binary = physical(binary, "pinned musl signal-process binary")
    record = read_json(record_path, "signal-process oracle record")
    expected = {"schema", "compiler", "musl_libc_archive", "object", "binary", "link_command"}
    if set(record) != expected or record["schema"] != ORACLE_SCHEMA:
        fail("signal-process oracle record schema drifted")
    assert_recorded_file(record["compiler"], oracle_cc, "oracle compiler")
    assert_recorded_file(record["musl_libc_archive"], Path("/opt/musl-1.2.6/lib/libc.a"), "oracle musl archive")
    assert_recorded_file(record["object"], object_path, "oracle object")
    assert_recorded_file(record["binary"], binary, "oracle binary")
    expected_command = [
        str(oracle_cc), "-static", "-fno-pie", "-no-pie", "-pthread", str(object_path),
        "-o", str(binary),
    ]
    if record["link_command"] != expected_command:
        fail("signal-process oracle link command drifted")
    return record


def validate_link_record(
    product: Path, object_path: Path, executable: Path, receipt: Path, linkage: str, record_path: Path
) -> dict[str, str]:
    """Call the shared sealed-link validator and write its immutable identity."""

    try:
        identity = validate_link(product, object_path, executable, receipt, linkage)
    except ProductEvidenceError as error:
        raise SignalProcessEvidenceError(f"signal-process {linkage} link validation failed: {error}") from error
    write_new_json(record_path, identity)
    return identity


def load_validated_link(
    product: Path, object_path: Path, executable: Path, receipt: Path, linkage: str, record_path: Path
) -> dict[str, str]:
    try:
        current = validate_link(product, object_path, executable, receipt, linkage)
    except ProductEvidenceError as error:
        raise SignalProcessEvidenceError(f"signal-process {linkage} link validation failed: {error}") from error
    recorded = read_json(record_path, f"signal-process {linkage} link record")
    if recorded != current:
        fail(f"signal-process {linkage} link identity drifted")
    return current


def run_in_process_group(command: Sequence[str], cwd: Path, timeout: float) -> tuple[str, bytes, bytes]:
    """Execute one subcase in a new session and kill its entire group on timeout."""

    if timeout <= 0 or timeout > MAX_TIMEOUT:
        fail(f"timeout must be in (0, {MAX_TIMEOUT}]")
    cwd = physical(cwd, "subcase working directory", directory=True)
    if not command or not all(isinstance(item, str) and item for item in command):
        fail("subcase command is empty or malformed")
    try:
        child = subprocess.Popen(
            list(command), cwd=cwd, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError as error:
        return f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode("utf-8", "replace")
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = child.communicate()
        return "TIMEOUT", stdout, stderr
    return str(child.returncode), stdout, stderr


def capture(command: Sequence[str], cwd: Path, timeout: float, output_base: Path) -> None:
    output_base = Path(os.path.abspath(output_base))
    physical(output_base.parent, "observation output parent", directory=True)
    paths = [output_base.with_suffix(suffix) for suffix in (".status", ".stdout", ".stderr")]
    if any(path.exists() or path.is_symlink() for path in paths):
        fail("observation output already exists or is unsafe")
    status, stdout, stderr = run_in_process_group(command, cwd, timeout)
    try:
        paths[0].write_bytes((status + "\n").encode("ascii"))
        paths[1].write_bytes(stdout)
        paths[2].write_bytes(stderr)
    except OSError as error:
        raise SignalProcessEvidenceError("cannot retain raw subcase observation") from error


def observation_files(base: Path, work: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in ("status", "stdout", "stderr"):
        path = require_within(base.with_suffix("." + name), work, f"raw {name} observation")
        result[name] = file_record(path)
    return result


def matched_observation(
    reference_base: Path, candidate_base: Path, work: Path, description: str
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Require both processes to succeed before accepting their exact raw match."""

    reference = observation_files(reference_base, work)
    candidate = observation_files(candidate_base, work)
    for role, observation in (("oracle", reference), ("candidate", candidate)):
        status = Path(observation["status"]["path"])
        if status.read_bytes() != b"0\n":
            fail(f"raw signal-process {role} status must succeed: {description}")
    for stream in ("status", "stdout", "stderr"):
        reference_path = Path(reference[stream]["path"])
        candidate_path = Path(candidate[stream]["path"])
        if reference[stream]["sha256"] != candidate[stream]["sha256"] or \
                reference_path.read_bytes() != candidate_path.read_bytes():
            fail(f"raw signal-process observation differs: {description} {stream}")
    return reference, candidate


def copied_payload_record(source: Path, execution: Path, description: str) -> dict[str, Any]:
    source = physical(source, f"{description} source")
    execution = physical(execution, f"{description} execution copy")
    source_record, execution_record = file_record(source), file_record(execution)
    if source_record["sha256"] != execution_record["sha256"]:
        fail(f"{description} execution copy differs from source")
    return {"source": source_record, "execution": execution_record}


def dynamic_payload_sources(product: Path, manifest: Path) -> dict[str, Path]:
    try:
        _manifest, files = _validate_dynamic_product(product)
    except ProductEvidenceError as error:
        raise SignalProcessEvidenceError(f"dynamic execution product validation failed: {error}") from error
    return {
        "share/crabc/manifest.json": manifest,
        **{relative: product / relative for relative in sorted(files)},
    }


def record_execution_payload(work: Path, product: Path) -> dict[str, Any]:
    """Seal product and consumer copy identities immediately before dynamic runs."""

    work = physical(work, "signal-process evidence work", directory=True)
    product, manifest, _driver = dynamic_product(product)
    execution_root = physical(work / "execution-root", "dynamic execution root", directory=True)
    product_payload = {
        relative: copied_payload_record(source, execution_root / relative, f"execution payload {relative}")
        for relative, source in dynamic_payload_sources(product, manifest).items()
    }
    consumers = []
    for mode in ("pie", "non-pie"):
        consumers.append({
            "mode": mode,
            **copied_payload_record(
                work / f"dynamic-{mode}", execution_root / f"consumer-{mode}",
                f"{mode} execution consumer",
            ),
        })
    record = {
        "schema": EXECUTION_PAYLOAD_SCHEMA,
        "product_manifest": file_record(manifest),
        "execution_root": str(execution_root),
        "product_payload": product_payload,
        "consumers": consumers,
    }
    write_new_json(work / "execution-payload.json", record)
    return record


def audit_copied_payload(value: object, source: Path, execution: Path, description: str) -> dict[str, Any]:
    record = exact_record(value, {"source", "execution"}, description)
    source = physical(source, f"{description} source")
    execution = physical(execution, f"{description} execution copy")
    assert_recorded_file(record["source"], source, f"{description} source")
    assert_recorded_file(record["execution"], execution, f"{description} execution")
    if sha256(source) != sha256(execution):
        fail(f"{description} execution copy differs from source")
    return record


def audit_execution_payload(work: Path, product: Path) -> dict[str, Any]:
    """Recheck the copy-time record before, after, and at final sealing."""

    work = physical(work, "signal-process evidence work", directory=True)
    product, manifest, _driver = dynamic_product(product)
    execution_root = physical(work / "execution-root", "dynamic execution root", directory=True)
    record_path = physical(work / "execution-payload.json", "execution payload record")
    record = read_json(record_path, "execution payload record")
    expected = {"schema", "product_manifest", "execution_root", "product_payload", "consumers"}
    if set(record) != expected or record["schema"] != EXECUTION_PAYLOAD_SCHEMA:
        fail("execution payload record schema drifted")
    assert_recorded_file(record["product_manifest"], manifest, "execution product manifest")
    if record["execution_root"] != str(execution_root):
        fail("execution root path drifted")
    sources = dynamic_payload_sources(product, manifest)
    payload = record["product_payload"]
    if not isinstance(payload, dict) or set(payload) != set(sources):
        fail("execution payload roster drifted")
    for relative, source in sources.items():
        audit_copied_payload(payload[relative], source, execution_root / relative, f"execution payload {relative}")
    consumers = record["consumers"]
    if not isinstance(consumers, list) or len(consumers) != 2:
        fail("execution consumer roster drifted")
    current_consumers = []
    for item, mode in zip(consumers, ("pie", "non-pie")):
        if not isinstance(item, dict) or item.get("mode") != mode:
            fail("execution consumer mode drifted")
        try:
            current = audit_copied_payload(
                {"source": item["source"], "execution": item["execution"]},
                work / f"dynamic-{mode}", execution_root / f"consumer-{mode}",
                f"execution consumer {mode}",
            )
        except SignalProcessEvidenceError as error:
            raise SignalProcessEvidenceError(f"execution consumer drifted: {mode}: {error}") from error
        current_consumers.append({"mode": mode, **current})
    return {
        "schema": EXECUTION_PAYLOAD_SCHEMA,
        "record": file_record(record_path),
        "product_manifest": file_record(manifest),
        "execution_root": str(execution_root),
        "consumers": current_consumers,
    }


def validated_execution_audit(path: Path, current: dict[str, Any], description: str) -> dict[str, Any]:
    path = physical(path, description)
    recorded = read_json(path, description)
    if recorded != current:
        fail(f"{description} drifted")
    return recorded

def record_observations(
    work: Path,
    static_product: Path | None,
    dynamic_product_path: Path,
    source: Path,
    object_path: Path,
    compile_audit: Path,
    oracle_cc: Path,
    oracle_binary: Path,
    oracle_record: Path,
) -> dict[str, Any]:
    """Revalidate every boundary and preserve all 12 raw oracle/product triples."""

    work = physical(work, "signal-process evidence work", directory=True)
    source = require_within(source, work, "signal-process source") if Path(source).is_relative_to(work) else physical(source, "signal-process source")
    object_path = require_within(object_path, work, "signal-process workload object")
    compile_audit = require_within(compile_audit, work, "signal-process compile audit")
    oracle_binary = require_within(oracle_binary, work, "pinned musl signal-process binary")
    oracle_record = require_within(oracle_record, work, "signal-process oracle record")
    compile_identity = validate_compile(dynamic_product_path, source, object_path, compile_audit)
    oracle_identity = validate_oracle(oracle_cc, object_path, oracle_binary, oracle_record)

    links: list[dict[str, str]] = []
    modes: list[tuple[str, Path, Path, str, Path]] = []
    if static_product is not None:
        static_product = supplied_product(ROOT, static_product, "static")
        modes.extend([
            ("static", static_product, work / "static", "static", work / "static.link.json"),
            ("static-pie", static_product, work / "static-pie", "static-pie", work / "static-pie.link.json"),
        ])
    dynamic_root = supplied_product(ROOT, dynamic_product_path, "dynamic")
    modes.extend([
        ("pie", dynamic_root, work / "dynamic-pie", "pie", work / "dynamic-pie.link.json"),
        ("non-pie", dynamic_root, work / "dynamic-non-pie", "non-pie", work / "dynamic-non-pie.link.json"),
    ])
    for _name, product, executable, linkage, link_record in modes:
        receipt = executable.with_suffix(".crabc-link.json") if linkage in {"pie", "non-pie"} else executable.with_suffix(".receipt.json")
        links.append(load_validated_link(product, object_path, executable, receipt, linkage, link_record))

    # The copied product and consumer identities were recorded before the first
    # dynamic launch, audited again immediately after the last one, and are
    # audited one final time here with the rest of the consumed boundary.
    execution_final = audit_execution_payload(work, dynamic_root)
    execution_pre = validated_execution_audit(
        work / "execution-pre.json", execution_final, "pre-execution payload audit"
    )
    execution_post = validated_execution_audit(
        work / "execution-post.json", execution_final, "post-execution payload audit"
    )
    observations: list[dict[str, Any]] = []
    observation_modes = ["static", "static-pie"] if static_product is not None else []
    observation_modes += ["pie-kernel", "pie-direct", "non-pie-kernel", "non-pie-direct"]
    for mode in observation_modes:
        for subcase in SIGNAL_PROCESS_SUBCASES:
            reference, candidate = matched_observation(
                work / f"oracle-{subcase}", work / f"{mode}-{subcase}", work,
                f"{mode} {subcase}",
            )
            observations.append({"mode": mode, "subcase": subcase, "reference": reference, "candidate": candidate})
    record = {
        "schema": OBSERVATION_SCHEMA,
        "subcases": list(SIGNAL_PROCESS_SUBCASES),
        "compile": compile_identity,
        "oracle": oracle_identity,
        "links": links,
        "execution": {
            "pre": file_record(work / "execution-pre.json"),
            "post": file_record(work / "execution-post.json"),
            "final": execution_final,
            "pre_identity": execution_pre,
            "post_identity": execution_post,
        },
        "observations": observations,
        "comparison": "exact raw status/stdout/stderr bytes; no documented source difference",
        "process_group_isolation": True,
    }
    write_new_json(work / "signal-process-observations.json", record)
    return record


def main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    input_parser = commands.add_parser("snapshot-compile-inputs")
    input_parser.add_argument("product", type=Path)
    input_parser.add_argument("source", type=Path)
    input_parser.add_argument("object", type=Path)
    input_parser.add_argument("snapshot", type=Path)
    compile_parser = commands.add_parser("record-compile")
    compile_parser.add_argument("product", type=Path)
    compile_parser.add_argument("source", type=Path)
    compile_parser.add_argument("object", type=Path)
    compile_parser.add_argument("snapshot", type=Path)
    compile_parser.add_argument("audit", type=Path)
    compile_validate = commands.add_parser("validate-compile")
    compile_validate.add_argument("product", type=Path)
    compile_validate.add_argument("source", type=Path)
    compile_validate.add_argument("object", type=Path)
    compile_validate.add_argument("audit", type=Path)
    oracle_parser = commands.add_parser("record-oracle")
    oracle_parser.add_argument("compiler", type=Path)
    oracle_parser.add_argument("object", type=Path)
    oracle_parser.add_argument("binary", type=Path)
    oracle_parser.add_argument("record", type=Path)
    link_parser = commands.add_parser("validate-link")
    link_parser.add_argument("product", type=Path)
    link_parser.add_argument("object", type=Path)
    link_parser.add_argument("executable", type=Path)
    link_parser.add_argument("receipt", type=Path)
    link_parser.add_argument("linkage", choices=("static", "static-pie", "pie", "non-pie"))
    link_parser.add_argument("record", type=Path)
    execution_record = commands.add_parser("record-execution-payload")
    execution_record.add_argument("work", type=Path)
    execution_record.add_argument("product", type=Path)
    execution_audit = commands.add_parser("audit-execution-payload")
    execution_audit.add_argument("work", type=Path)
    execution_audit.add_argument("product", type=Path)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--timeout", type=float, required=True)
    capture_parser.add_argument("--cwd", type=Path, required=True)
    capture_parser.add_argument("--output-base", type=Path, required=True)
    capture_parser.add_argument("command", nargs=argparse.REMAINDER)
    seal_parser = commands.add_parser("seal")
    seal_parser.add_argument("--static-product", type=Path)
    seal_parser.add_argument("--dynamic-product", type=Path, required=True)
    seal_parser.add_argument("--source", type=Path, required=True)
    seal_parser.add_argument("--object", type=Path, required=True)
    seal_parser.add_argument("--compile-audit", type=Path, required=True)
    seal_parser.add_argument("--oracle-compiler", type=Path, required=True)
    seal_parser.add_argument("--oracle-binary", type=Path, required=True)
    seal_parser.add_argument("--oracle-record", type=Path, required=True)
    seal_parser.add_argument("work", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.action == "snapshot-compile-inputs":
            snapshot_compile_inputs(parsed.product, parsed.source, parsed.object, parsed.snapshot)
        elif parsed.action == "record-compile":
            record_compile(parsed.product, parsed.source, parsed.object, parsed.snapshot, parsed.audit)
        elif parsed.action == "validate-compile":
            json.dump(validate_compile(parsed.product, parsed.source, parsed.object, parsed.audit), sys.stdout, sort_keys=True, separators=(",", ":"))
            sys.stdout.write("\n")
        elif parsed.action == "record-oracle":
            record_oracle(parsed.compiler, parsed.object, parsed.binary, parsed.record)
        elif parsed.action == "validate-link":
            validate_link_record(parsed.product, parsed.object, parsed.executable, parsed.receipt, parsed.linkage, parsed.record)
        elif parsed.action == "record-execution-payload":
            record_execution_payload(parsed.work, parsed.product)
        elif parsed.action == "audit-execution-payload":
            json.dump(audit_execution_payload(parsed.work, parsed.product), sys.stdout, sort_keys=True, separators=(",", ":"))
            sys.stdout.write("\n")
        elif parsed.action == "capture":
            command = list(parsed.command)
            if command[:1] == ["--"]:
                command = command[1:]
            capture(command, parsed.cwd, parsed.timeout, parsed.output_base)
        else:
            record_observations(
                parsed.work, parsed.static_product, parsed.dynamic_product, parsed.source, parsed.object,
                parsed.compile_audit, parsed.oracle_compiler, parsed.oracle_binary, parsed.oracle_record,
            )
    except (OSError, SignalProcessEvidenceError) as error:
        print(f"owned signal-process evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
